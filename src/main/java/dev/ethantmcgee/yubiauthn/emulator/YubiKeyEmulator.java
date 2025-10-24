package dev.ethantmcgee.yubiauthn.emulator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.exception.CredentialNotFoundException;
import dev.ethantmcgee.yubiauthn.exception.InvalidConfigurationException;
import dev.ethantmcgee.yubiauthn.exception.InvalidRequestException;
import dev.ethantmcgee.yubiauthn.model.AssertionResponse;
import dev.ethantmcgee.yubiauthn.model.AttestationFormat;
import dev.ethantmcgee.yubiauthn.model.AttestationObject;
import dev.ethantmcgee.yubiauthn.model.AttestationStatement;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorAttachmentType;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorData;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorSelection;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.model.CredPropsResult;
import dev.ethantmcgee.yubiauthn.model.CredentialType;
import dev.ethantmcgee.yubiauthn.model.ExtensionResults;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredential;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialAssertionOptions;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialCreationOptions;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialRef;
import dev.ethantmcgee.yubiauthn.model.PublicKeyParameterType;
import dev.ethantmcgee.yubiauthn.model.RegistrationResponse;
import dev.ethantmcgee.yubiauthn.model.ResidentKeyType;
import dev.ethantmcgee.yubiauthn.model.StoredCredential;
import dev.ethantmcgee.yubiauthn.model.TransportType;
import dev.ethantmcgee.yubiauthn.model.UserVerificationType;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Builder;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

@Builder(toBuilder = true, buildMethodName = "buildInternal")
public class YubiKeyEmulator {
  private final ObjectMapper jsonMapper = JsonUtil.getJsonMapper();
  private final Map<String, StoredCredential> credentials = new HashMap<>();

  private UUID aaguid;
  private String deviceIdentifier;
  private String description;
  private KeyPair attestationKeyPair;
  private X509Certificate attestationCertificate;
  @Builder.Default private int signatureCounter = 0;

  @Builder.Default private List<TransportType> transports = List.of();
  @Builder.Default private List<COSEAlgorithmIdentifier> supportedAlgorithms = List.of();

  @Builder.Default
  private List<AuthenticatorAttachmentType> supportedAttachmentTypes =
      List.of(AuthenticatorAttachmentType.CROSS_PLATFORM, AuthenticatorAttachmentType.PLATFORM);

  @Builder.Default private boolean supportsUserPresence = false;
  @Builder.Default private boolean supportsUserVerification = false;
  @Builder.Default private boolean supportsResidentKey = false;
  @Builder.Default private boolean supportsEnterpriseAttestation = false;

  @Builder.Default private boolean supportsCredProtect = false;
  @Builder.Default private boolean supportsMinPinLength = false;
  private Integer pinLength;

  @Builder.Default private boolean backupEligible = false;
  @Builder.Default private boolean backupState = false;

  @Builder.Default private AttestationFormat attestationFormat = AttestationFormat.PACKED;

  public static class YubiKeyEmulatorBuilder {
    public YubiKeyEmulator build() {
      try {
        YubiKeyEmulator res = buildInternal();
        res.init();
        return res;
      } catch (Exception e) {
        throw new RuntimeException("Failed to initialize YubiKeyEmulator", e);
      }
    }
  }

  private void init()
      throws InvalidAlgorithmParameterException,
          NoSuchAlgorithmException,
          CertificateException,
          OperatorCreationException,
          CertIOException {
    if (attestationKeyPair == null) {
      attestationKeyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    }
    if (attestationCertificate == null) {
      attestationCertificate =
          CryptoUtils.generateAttestationCertificate(attestationKeyPair, deviceIdentifier, aaguid);
    }
  }

  public PublicKeyCredential<RegistrationResponse> create(String json) throws Exception {
    return create(jsonMapper.readValue(json, PublicKeyCredentialCreationOptions.class));
  }

  public PublicKeyCredential<RegistrationResponse> create(
      PublicKeyCredentialCreationOptions options) throws Exception {
    if (aaguid == null) {
      throw new InvalidConfigurationException("A valid uuid must be specified for the AAGUID");
    }

    if (deviceIdentifier == null) {
      throw new InvalidConfigurationException("A valid device identifier must be specified");
    }

    if (supportedAttachmentTypes.isEmpty()) {
      throw new InvalidConfigurationException(
          "At least one authenticator attachment type must be supported");
    }

    if (!canAuthenticatorBeUsed(options.authenticatorSelection())) {
      throw new InvalidRequestException(
          "Authenticator does not meet the selection criteria specified in the request");
    }

    COSEAlgorithmIdentifier alg = findMatchingAlgorithm(options.pubKeyCredParams());
    if (alg == null) {
      throw new InvalidRequestException("No matching public key algorithm");
    }

    AuthenticatorAttachmentType attachmentType =
        options.authenticatorSelection().authenticatorAttachment() != null
            ? options.authenticatorSelection().authenticatorAttachment()
            : supportedAttachmentTypes.getFirst();

    Integer credentialProtectionPolicy = null;
    if (options.extensions() != null && options.extensions().credentialProtectionPolicy() != null) {
      credentialProtectionPolicy =
          options.extensions().credentialProtectionPolicy().getResponseValue();
    }

    byte[] credentialId = CryptoUtils.generateCredentialId();
    KeyPair credentialKeyPair = CryptoUtils.generateKeyPair(alg);
    byte[] credentialPublicKey =
        CryptoUtils.encodeCOSEPublicKey(credentialKeyPair.getPublic(), alg);
    byte[] attestedCredentialData =
        CryptoUtils.createAttestedCredentialData(
            aaguidToBytes(), credentialId, credentialPublicKey);

    AuthenticatorData authData =
        new AuthenticatorData.Builder()
            .rpId(options.rp().id())
            .userPresent(true)
            .userVerified(isUserVerified(options.authenticatorSelection().userVerification()))
            .backupEligible(backupEligible)
            .backupState(backupState)
            .attestedCredentialData(attestedCredentialData)
            .extensions(getExtensionBytes(credentialProtectionPolicy))
            .signCount(signatureCounter++)
            .build();

    Map<String, Object> clientData = new HashMap<>();
    clientData.put("type", "webauthn.create");
    clientData.put("challenge", options.challenge());
    clientData.put("origin", "https://" + options.rp().id());
    clientData.put("crossOrigin", false);

    String clientDataJSON = jsonMapper.writeValueAsString(clientData);
    byte[] clientDataHash =
        MessageDigest.getInstance("SHA-256")
            .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));

    ByteArrayOutputStream sigData = new ByteArrayOutputStream();
    sigData.write(authData.encode());
    sigData.write(clientDataHash);
    byte[] signature =
        CryptoUtils.sign(
            sigData.toByteArray(), attestationKeyPair.getPrivate(), COSEAlgorithmIdentifier.ES256);

    AttestationStatement attStmt =
        new AttestationStatement(
            signature, attestationCertificate.getEncoded(), COSEAlgorithmIdentifier.ES256);
    byte[] attestationObject =
        encodeAttestationObject(new AttestationObject(attestationFormat, authData, attStmt));

    credentials.put(
        Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId),
        new StoredCredential(
            credentialId,
            credentialKeyPair,
            alg,
            options.rp().id(),
            options.user().id(),
            signatureCounter,
            supportsResidentKey
                && options.authenticatorSelection().residentKey() == ResidentKeyType.REQUIRED,
            credentialProtectionPolicy));

    return new PublicKeyCredential<>(
        attachmentType,
        Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId),
        Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId),
        new RegistrationResponse(
            Base64.getUrlEncoder().withoutPadding().encodeToString(clientDataJSON.getBytes()),
            Base64.getUrlEncoder().withoutPadding().encodeToString(attestationObject),
            transports,
            authData,
            alg),
        CredentialType.PUBLIC_KEY,
        new ExtensionResults(
            supportsCredProtect
                ? new CredPropsResult(
                    supportsResidentKey
                        && options.authenticatorSelection().residentKey()
                            == ResidentKeyType.REQUIRED)
                : null,
            supportsCredProtect && credentialProtectionPolicy != null
                ? credentialProtectionPolicy
                : null,
            supportsMinPinLength ? pinLength : null));
  }

  private boolean canAuthenticatorBeUsed(AuthenticatorSelection authenticatorSelection) {
    if (authenticatorSelection.authenticatorAttachment() != null
        && !supportedAttachmentTypes.contains(authenticatorSelection.authenticatorAttachment())) {
      return false;
    }

    if (authenticatorSelection.requireResidentKey() != null
        && authenticatorSelection.requireResidentKey()
        && !supportsResidentKey) {
      return false;
    }

    if (authenticatorSelection.residentKey() == ResidentKeyType.REQUIRED && !supportsResidentKey) {
      return false;
    }

    if (authenticatorSelection.userVerification() == UserVerificationType.REQUIRED
        && !supportsUserVerification) {
      return false;
    }
    return true;
  }

  private COSEAlgorithmIdentifier findMatchingAlgorithm(
      List<PublicKeyParameterType> requestedAlgorithms) {
    for (PublicKeyParameterType requestedAlgorithm : requestedAlgorithms) {
      if (supportedAlgorithms.contains(requestedAlgorithm.alg())) {
        return requestedAlgorithm.alg();
      }
    }
    return null;
  }

  private boolean isUserVerified(UserVerificationType userVerification) {
    boolean userVerified = false;
    if (userVerification == UserVerificationType.REQUIRED) {
      userVerified = true;
    } else if (supportsUserVerification) {
      userVerified = true;
    }
    return userVerified;
  }

  private byte[] aaguidToBytes() {
    ByteBuffer buffer = ByteBuffer.wrap(new byte[16]);
    buffer.putLong(aaguid.getMostSignificantBits());
    buffer.putLong(aaguid.getLeastSignificantBits());
    return buffer.array();
  }

  private byte[] getExtensionBytes(Integer credentialProtectionPolicy) {
    byte[] extensionsBytes = null;
    if (supportsCredProtect && credentialProtectionPolicy != null) {
      CBORObject extensionsMap = CBORObject.NewMap();
      extensionsMap.Add("credProtect", credentialProtectionPolicy);
      extensionsBytes = extensionsMap.EncodeToBytes();
    }
    return extensionsBytes;
  }

  private byte[] encodeAttestationObject(AttestationObject attestationObject) throws Exception {
    // Create CBOR map with canonical ordering: fmt (3 chars), attStmt (7 chars), authData (8 chars)
    CBORObject attestationMap = CBORObject.NewMap();

    // Add in canonical order for proper CBOR encoding
    attestationMap.Add("fmt", attestationObject.fmt().getValue());

    // Build attStmt map
    CBORObject attStmtMap = CBORObject.NewMap();
    if (!attestationObject.fmt().equals(AttestationFormat.NONE)) {
      // For packed attestation, add in canonical order: alg (3), sig (3), x5c (3)
      // Same length, so lexicographic: alg < sig < x5c
      if (attestationObject.attStmt().alg() != null) {
        attStmtMap.Add("alg", attestationObject.attStmt().alg().getValue());
      }
      if (attestationObject.attStmt().sig() != null) {
        attStmtMap.Add("sig", attestationObject.attStmt().sig());
      }
      if (attestationObject.attStmt().x5c() != null
          && attestationObject.attStmt().x5c().length > 0) {
        CBORObject x5cArray = CBORObject.NewArray();
        x5cArray.Add(attestationObject.attStmt().x5c());
        attStmtMap.Add("x5c", x5cArray);
      }
    }
    attestationMap.Add("attStmt", attStmtMap);

    attestationMap.Add("authData", attestationObject.authData().encode());

    return attestationMap.EncodeToBytes();
  }

  public PublicKeyCredential<AssertionResponse> get(String json) throws Exception {
    return get(jsonMapper.readValue(json, PublicKeyCredentialAssertionOptions.class));
  }

  public PublicKeyCredential<AssertionResponse> get(PublicKeyCredentialAssertionOptions options)
      throws Exception {
    StoredCredential credential = findMatchingCredential(options);

    if (credential == null) {
      throw new CredentialNotFoundException("No matching credential found for RP ID");
    }

    AuthenticatorData authData =
        new AuthenticatorData.Builder()
            .rpId(credential.rpId())
            .userPresent(true)
            .userVerified(isUserVerified(options.userVerification()))
            .backupEligible(backupEligible)
            .backupState(backupState)
            .signCount(signatureCounter++)
            .extensions(getExtensionBytes(credential.credentialProtectionPolicy()))
            .build();

    Map<String, Object> clientData = new HashMap<>();
    clientData.put("type", "webauthn.get");
    clientData.put("challenge", options.challenge());
    clientData.put("origin", "https://" + credential.rpId());
    clientData.put("crossOrigin", false);

    String clientDataJSON = jsonMapper.writeValueAsString(clientData);
    byte[] clientDataHash =
        MessageDigest.getInstance("SHA-256")
            .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));

    ByteArrayOutputStream sigData = new ByteArrayOutputStream();
    sigData.write(authData.encode());
    sigData.write(clientDataHash);

    byte[] signature =
        CryptoUtils.sign(
            sigData.toByteArray(), credential.keyPair().getPrivate(), credential.algorithm());

    String credentialKey =
        Base64.getUrlEncoder().withoutPadding().encodeToString(credential.credentialId());
    credentials.put(
        credentialKey,
        new StoredCredential(
            credential.credentialId(),
            credential.keyPair(),
            credential.algorithm(),
            credential.rpId(),
            credential.userHandle(),
            signatureCounter,
            credential.rk(),
            credential.credentialProtectionPolicy()));

    return new PublicKeyCredential<>(
        supportedAttachmentTypes.getFirst(),
        Base64.getUrlEncoder().withoutPadding().encodeToString(credential.credentialId()),
        Base64.getUrlEncoder().withoutPadding().encodeToString(credential.credentialId()),
        new AssertionResponse(
            Base64.getUrlEncoder().withoutPadding().encodeToString(clientDataJSON.getBytes()),
            transports,
            authData,
            credential.algorithm(),
            Base64.getUrlEncoder().withoutPadding().encodeToString(signature)),
        CredentialType.PUBLIC_KEY,
        new ExtensionResults(
            supportsCredProtect
                ? new CredPropsResult(supportsResidentKey && credential.rk())
                : null,
            supportsCredProtect && credential.credentialProtectionPolicy() != null
                ? credential.credentialProtectionPolicy()
                : null,
            supportsMinPinLength ? pinLength : null));
  }

  private StoredCredential findMatchingCredential(PublicKeyCredentialAssertionOptions options) {
    if (options.allowCredentials() != null && !options.allowCredentials().isEmpty()) {
      // Respect the order of allowCredentials - return the first match
      for (PublicKeyCredentialRef descriptor : options.allowCredentials()) {
        if (credentials.containsKey(descriptor.id())) {
          return credentials.get(descriptor.id());
        }
      }
      return null;
    } else {
      // No allowCredentials specified, find any credential for this RP ID
      String rpId = options.rpId();
      for (StoredCredential cred : credentials.values()) {
        if (cred.rpId().equals(rpId)) {
          return cred;
        }
      }
      return null;
    }
  }
}
