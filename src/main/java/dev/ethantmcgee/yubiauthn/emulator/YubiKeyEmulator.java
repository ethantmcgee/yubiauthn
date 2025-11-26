package dev.ethantmcgee.yubiauthn.emulator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.emulator.scp.Scp11bHandler;
import dev.ethantmcgee.yubiauthn.exception.CredentialNotFoundException;
import dev.ethantmcgee.yubiauthn.exception.CryptographicException;
import dev.ethantmcgee.yubiauthn.exception.EncodingException;
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
import dev.ethantmcgee.yubiauthn.storage.CredentialStore;
import dev.ethantmcgee.yubiauthn.storage.InMemoryCredentialStore;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.Builder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Emulates a FIDO2/WebAuthn authenticator with configurable characteristics.
 *
 * <p>This class provides a software implementation of a FIDO2 authenticator that can be used for
 * testing WebAuthn flows without requiring physical hardware. It supports credential creation
 * (registration) and authentication assertion operations.
 *
 * <p>The emulator can be configured to mimic specific authenticator models (like YubiKey 5C NFC)
 * with their actual capabilities, including supported algorithms, transport types, and extension
 * support.
 *
 * @see Yubikey for factory methods creating pre-configured emulator instances
 */
@Builder(toBuilder = true, buildMethodName = "buildInternal")
public class YubiKeyEmulator implements SmartCardConnection {
  private final ObjectMapper jsonMapper = JsonUtil.getJsonMapper();

  private UUID aaguid;
  private String deviceIdentifier;
  private String description;
  private KeyPair attestationKeyPair;
  private X509Certificate attestationCertificate;
  @Builder.Default private AtomicInteger signatureCounter = new AtomicInteger(0);
  @Builder.Default private CredentialStore credentialStore = new InMemoryCredentialStore();

  @Builder.Default
  private COSEAlgorithmIdentifier attestationAlgorithm = COSEAlgorithmIdentifier.ES256;

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

  // SCP11b handler and APDU processor
  private transient ApduHandler apduHandler;
  private transient KeyPair scp11bKeyPair;
  private transient X509Certificate scp11bCertificate;

  /**
   * Builder class for constructing YubiKeyEmulator instances.
   *
   * <p>This builder provides a fluent API for configuring all aspects of the emulator, including
   * cryptographic capabilities, supported features, and device characteristics.
   */
  public static class YubiKeyEmulatorBuilder {
    /**
     * Builds and initializes a YubiKeyEmulator instance.
     *
     * @return a fully initialized YubiKeyEmulator
     * @throws RuntimeException if initialization fails
     */
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
      throws CryptographicException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    if (attestationKeyPair == null) {
      attestationKeyPair = CryptoUtils.generateKeyPair(attestationAlgorithm);
    }
    if (attestationCertificate == null) {
      attestationCertificate =
          CryptoUtils.generateAttestationCertificate(attestationKeyPair, deviceIdentifier, aaguid);
    }

    // Initialize SCP11b key pair and certificate
    initScp11b();
  }

  private void initScp11b() {
    try {
      // Generate ECDH key pair for SCP11b
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
      kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
      scp11bKeyPair = kpg.generateKeyPair();

      // Generate self-signed certificate for SCP11b
      scp11bCertificate = generateScp11bCertificate(scp11bKeyPair);

      // Initialize APDU handler
      Scp11bHandler scp11bHandler = new Scp11bHandler(scp11bKeyPair, List.of(scp11bCertificate));
      apduHandler = new ApduHandler(scp11bHandler, "5.7.4", new byte[] {0x01, 0x02, 0x03, 0x04});
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize SCP11b", e);
    }
  }

  private X509Certificate generateScp11bCertificate(KeyPair keyPair) throws Exception {
    long now = System.currentTimeMillis();
    Date startDate = new Date(now);
    Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

    X500Name issuer = new X500Name("CN=YubiKey SD Attestation");
    X500Name subject = new X500Name("CN=YubiKey SD Attestation 13:01");
    BigInteger serialNumber = BigInteger.valueOf(now);

    SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

    X509v3CertificateBuilder certBuilder =
        new X509v3CertificateBuilder(
            issuer, serialNumber, startDate, endDate, subject, subjectPublicKeyInfo);

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(new BouncyCastleProvider())
            .build(keyPair.getPrivate());

    return new JcaX509CertificateConverter()
        .setProvider(new BouncyCastleProvider())
        .getCertificate(certBuilder.build(signer));
  }

  /**
   * Creates a new credential from JSON-encoded PublicKeyCredentialCreationOptions.
   *
   * @param json the JSON string containing credential creation options
   * @return a PublicKeyCredential containing the registration response
   * @throws InvalidConfigurationException if the emulator is misconfigured
   * @throws InvalidRequestException if the request is invalid or unsupported
   * @throws CryptographicException if cryptographic operations fail
   * @throws EncodingException if encoding operations fail
   */
  public PublicKeyCredential<RegistrationResponse> create(String json)
      throws InvalidConfigurationException,
          InvalidRequestException,
          CryptographicException,
          EncodingException {
    if (json == null || json.isEmpty()) {
      throw new InvalidRequestException("JSON must not be null or empty");
    }
    try {
      return create(jsonMapper.readValue(json, PublicKeyCredentialCreationOptions.class));
    } catch (InvalidConfigurationException
        | InvalidRequestException
        | CryptographicException
        | EncodingException e) {
      throw e;
    } catch (Exception e) {
      throw new EncodingException("Failed to parse credential creation options", e);
    }
  }

  /**
   * Creates a new credential based on the provided options.
   *
   * <p>This method emulates the authenticatorMakeCredential operation as defined in the WebAuthn
   * specification. It generates a new key pair, creates an attestation object, and returns a
   * credential that can be registered with a relying party.
   *
   * @param options the credential creation options from the relying party
   * @return a PublicKeyCredential containing the registration response
   * @throws InvalidConfigurationException if the emulator is misconfigured
   * @throws InvalidRequestException if the request is invalid or unsupported
   * @throws CryptographicException if cryptographic operations fail
   * @throws EncodingException if encoding operations fail
   */
  public PublicKeyCredential<RegistrationResponse> create(
      PublicKeyCredentialCreationOptions options)
      throws InvalidConfigurationException,
          InvalidRequestException,
          CryptographicException,
          EncodingException {
    // Validate configuration
    if (options == null) {
      throw new InvalidRequestException("Credential creation options must not be null");
    }
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

    // For fido-u2f, only ES256 is supported
    if (attestationFormat == AttestationFormat.FIDO_U2F && alg != COSEAlgorithmIdentifier.ES256) {
      throw new InvalidRequestException(
          "fido-u2f attestation format only supports ES256 algorithm");
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

    try {
      byte[] credentialId = CryptoUtils.generateCredentialId();
      KeyPair credentialKeyPair = CryptoUtils.generateKeyPair(alg);
      byte[] credentialPublicKey =
          CryptoUtils.encodeCOSEPublicKey(credentialKeyPair.getPublic(), alg);
      byte[] attestedCredentialData =
          CryptoUtils.createAttestedCredentialData(
              aaguidToBytes(), credentialId, credentialPublicKey);

      int currentSignCount = signatureCounter.getAndIncrement();

      AuthenticatorData authData =
          new AuthenticatorData.Builder()
              .rpId(options.rp().id())
              .userPresent(true)
              .userVerified(isUserVerified(options.authenticatorSelection().userVerification()))
              .backupEligible(backupEligible)
              .backupState(backupState)
              .attestedCredentialData(attestedCredentialData)
              .extensions(getExtensionBytes(credentialProtectionPolicy))
              .signCount(currentSignCount)
              .build();

      Map<String, Object> clientData = new java.util.HashMap<>();
      clientData.put("type", "webauthn.create");
      clientData.put("challenge", options.challenge());
      clientData.put("origin", "https://" + options.rp().id());
      clientData.put("crossOrigin", false);

      String clientDataJSON = jsonMapper.writeValueAsString(clientData);
      byte[] clientDataHash =
          MessageDigest.getInstance("SHA-256")
              .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));

      byte[] signature;
      AttestationStatement attStmt;

      if (attestationFormat == AttestationFormat.FIDO_U2F) {
        // FIDO U2F attestation format
        byte[] rpIdHash =
            MessageDigest.getInstance("SHA-256")
                .digest(options.rp().id().getBytes(StandardCharsets.UTF_8));
        byte[] u2fPublicKey =
            CryptoUtils.encodeU2FPublicKey(
                (java.security.interfaces.ECPublicKey) credentialKeyPair.getPublic());
        byte[] u2fSigData =
            CryptoUtils.createU2FSignatureData(
                rpIdHash, clientDataHash, credentialId, u2fPublicKey);
        signature =
            CryptoUtils.sign(u2fSigData, attestationKeyPair.getPrivate(), attestationAlgorithm);
        // U2F attStmt only has sig and x5c (no alg field)
        attStmt = new AttestationStatement(signature, attestationCertificate.getEncoded(), null);
      } else if (attestationFormat == AttestationFormat.PACKED) {
        // Packed attestation format
        ByteArrayOutputStream sigData = new ByteArrayOutputStream();
        sigData.write(authData.encode());
        sigData.write(clientDataHash);
        signature =
            CryptoUtils.sign(
                sigData.toByteArray(), attestationKeyPair.getPrivate(), attestationAlgorithm);
        attStmt =
            new AttestationStatement(
                signature, attestationCertificate.getEncoded(), attestationAlgorithm);
      } else {
        // NONE format
        signature = new byte[0];
        attStmt = new AttestationStatement(signature, null, null);
      }

      byte[] attestationObject =
          encodeAttestationObject(new AttestationObject(attestationFormat, authData, attStmt));

      String credentialIdString =
          Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
      credentialStore.store(
          credentialIdString,
          new StoredCredential(
              credentialId,
              credentialKeyPair,
              alg,
              options.rp().id(),
              options.user().id(),
              currentSignCount,
              supportsResidentKey
                  && options.authenticatorSelection().residentKey() == ResidentKeyType.REQUIRED,
              credentialProtectionPolicy));

      return new PublicKeyCredential<>(
          attachmentType,
          credentialIdString,
          credentialIdString,
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
    } catch (InvalidConfigurationException
        | InvalidRequestException
        | CryptographicException
        | EncodingException e) {
      throw e;
    } catch (Exception e) {
      throw new CryptographicException("Failed to create credential", e);
    }
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

    return authenticatorSelection.userVerification() != UserVerificationType.REQUIRED
        || supportsUserVerification;
  }

  private COSEAlgorithmIdentifier findMatchingAlgorithm(
      List<PublicKeyParameterType> requestedAlgorithms) {
    if (requestedAlgorithms == null || requestedAlgorithms.isEmpty()) {
      return null;
    }
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

  private byte[] encodeAttestationObject(AttestationObject attestationObject)
      throws EncodingException {
    try {
      // Create CBOR map with canonical ordering: fmt (3 chars), attStmt (7 chars), authData (8
      // chars)
      CBORObject attestationMap = CBORObject.NewMap();

      // Add in canonical order for proper CBOR encoding
      attestationMap.Add("fmt", attestationObject.fmt().getValue());

      // Build attStmt map
      CBORObject attStmtMap = CBORObject.NewMap();
      if (attestationObject.fmt().equals(AttestationFormat.FIDO_U2F)) {
        // FIDO U2F format: only sig and x5c (no alg field)
        // Canonical order: sig (3) < x5c (3), lexicographic
        if (attestationObject.attStmt().sig() != null) {
          attStmtMap.Add("sig", attestationObject.attStmt().sig());
        }
        if (attestationObject.attStmt().x5c() != null
            && attestationObject.attStmt().x5c().length > 0) {
          CBORObject x5cArray = CBORObject.NewArray();
          x5cArray.Add(attestationObject.attStmt().x5c());
          attStmtMap.Add("x5c", x5cArray);
        }
      } else if (attestationObject.fmt().equals(AttestationFormat.PACKED)) {
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
      // NONE format: empty attStmt map

      attestationMap.Add("attStmt", attStmtMap);
      attestationMap.Add("authData", attestationObject.authData().encode());

      return attestationMap.EncodeToBytes();
    } catch (Exception e) {
      throw new EncodingException("Failed to encode attestation object", e);
    }
  }

  /**
   * Performs authentication assertion from JSON-encoded PublicKeyCredentialRequestOptions.
   *
   * @param json the JSON string containing credential request options
   * @return a PublicKeyCredential containing the assertion response
   * @throws CredentialNotFoundException if no matching credential is found
   * @throws CryptographicException if cryptographic operations fail
   * @throws EncodingException if encoding operations fail
   */
  public PublicKeyCredential<AssertionResponse> get(String json)
      throws CredentialNotFoundException, CryptographicException, EncodingException {
    if (json == null || json.isEmpty()) {
      throw new EncodingException("JSON must not be null or empty");
    }
    try {
      return get(jsonMapper.readValue(json, PublicKeyCredentialAssertionOptions.class));
    } catch (CredentialNotFoundException | CryptographicException | EncodingException e) {
      throw e;
    } catch (Exception e) {
      throw new EncodingException("Failed to parse credential request options", e);
    }
  }

  /**
   * Performs authentication assertion based on the provided options.
   *
   * <p>This method emulates the authenticatorGetAssertion operation as defined in the WebAuthn
   * specification. It finds a matching credential, generates a signature, and returns an assertion
   * that can be verified by the relying party.
   *
   * @param options the credential request options from the relying party
   * @return a PublicKeyCredential containing the assertion response
   * @throws CredentialNotFoundException if no matching credential is found
   * @throws CryptographicException if cryptographic operations fail
   * @throws EncodingException if encoding operations fail
   */
  public PublicKeyCredential<AssertionResponse> get(PublicKeyCredentialAssertionOptions options)
      throws CredentialNotFoundException, CryptographicException, EncodingException {
    if (options == null) {
      throw new CredentialNotFoundException("Credential request options must not be null");
    }

    StoredCredential credential = findMatchingCredential(options);

    if (credential == null) {
      throw new CredentialNotFoundException("No matching credential found for RP ID");
    }

    try {
      int currentSignCount = signatureCounter.getAndIncrement();

      AuthenticatorData authData =
          new AuthenticatorData.Builder()
              .rpId(credential.rpId())
              .userPresent(true)
              .userVerified(isUserVerified(options.userVerification()))
              .backupEligible(backupEligible)
              .backupState(backupState)
              .signCount(currentSignCount)
              .extensions(getExtensionBytes(credential.credentialProtectionPolicy()))
              .build();

      Map<String, Object> clientData = new java.util.HashMap<>();
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
      credentialStore.store(
          credentialKey,
          new StoredCredential(
              credential.credentialId(),
              credential.keyPair(),
              credential.algorithm(),
              credential.rpId(),
              credential.userHandle(),
              currentSignCount,
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
    } catch (CredentialNotFoundException | CryptographicException e) {
      throw e;
    } catch (Exception e) {
      throw new CryptographicException("Failed to generate assertion", e);
    }
  }

  private StoredCredential findMatchingCredential(PublicKeyCredentialAssertionOptions options) {
    if (options.allowCredentials() != null && !options.allowCredentials().isEmpty()) {
      // Respect the order of allowCredentials - return the first match
      for (PublicKeyCredentialRef descriptor : options.allowCredentials()) {
        var credential = credentialStore.retrieve(descriptor.id());
        if (credential.isPresent()) {
          return credential.get();
        }
      }
      return null;
    } else {
      // No allowCredentials specified, find any credential for this RP ID
      String rpId = options.rpId();
      var credentials = credentialStore.findByRpId(rpId);
      return credentials.isEmpty() ? null : credentials.iterator().next();
    }
  }

  @Override
  public byte[] sendAndReceive(byte[] bytes) {
    // tell the programmer what connection we are using (1 = usb, 2 = nfc)
    if (bytes.length == 4 && bytes[0] == -1 && bytes[1] == -1 && bytes[2] == 1) {
      if (bytes[3]
          == 0) { // if the programmer is asking, respond with default, echo back expected value
        bytes[3] = 2; // default to nfc
      }
      return new byte[] {bytes[3], (byte) (0x9000 >> 8), (byte) (0x9000 & 0xFF)};
    }

    // Handle APDU commands using the APDU handler
    return apduHandler.processApdu(bytes);
  }
}
