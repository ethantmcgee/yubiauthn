package dev.ethantmcgee.yubiauthn.emulator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.exception.CredentialNotFoundException;
import dev.ethantmcgee.yubiauthn.exception.CryptoException;
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
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Builder;

/**
 * YubiKeyEmulator simulates a YubiKey authenticator for WebAuthn operations.
 *
 * <p>This emulator implements the WebAuthn authenticator model and can be configured to simulate
 * various YubiKey models with different capabilities. It supports credential creation
 * (registration) and credential assertion (authentication) operations.
 *
 * <h2>Features</h2>
 *
 * <ul>
 *   <li>Supports multiple COSE algorithms (ES256, ES384, ES512, RS256, RS384, RS512, EdDSA)
 *   <li>Configurable authenticator attachment types (platform, cross-platform)
 *   <li>User presence and user verification support
 *   <li>Resident key (discoverable credential) support
 *   <li>Extension support: credProtect, credProps, minPinLength
 *   <li>Backup eligible and backup state flags
 *   <li>Attestation with self-signed certificates
 *   <li>In-memory credential storage
 * </ul>
 *
 * <h2>Limitations</h2>
 *
 * <ul>
 *   <li>Supports "packed", "fido-u2f", and "none" attestation formats
 *   <li>Credentials are stored in memory only (not persisted)
 *   <li>No actual user interaction or biometric verification
 *   <li>Thread-safe only for read operations (not suitable for concurrent writes)
 *   <li>Self-attestation only (not production-grade attestation chain)
 * </ul>
 *
 * @see dev.ethantmcgee.yubiauthn.emulator.Yubikey Yubikey for pre-configured emulator builders
 */
@Builder(toBuilder = true, buildMethodName = "buildInternal")
public class YubiKeyEmulator {
  private final ObjectMapper jsonMapper = JsonUtil.getJsonMapper();
  private final ObjectMapper cborMapper = createCborMapper();
  private final Map<String, StoredCredential> credentials = new HashMap<>();

  @Builder.Default private String aaguid = null;
  @Builder.Default private String description = null;
  @Builder.Default private KeyPair attestationKeyPair = null;
  @Builder.Default private X509Certificate attestationCertificate = null;
  @Builder.Default private String attestationSubject = null;
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
  @Builder.Default private Integer pinLength = null;

  @Builder.Default private boolean backupEligible = false;
  @Builder.Default private boolean backupState = false;

  @Builder.Default private AttestationFormat attestationFormat = AttestationFormat.PACKED;

  /**
   * Creates a properly configured ObjectMapper for CBOR encoding.
   *
   * <p>This method configures Jackson's CBORFactory to ensure compatibility with WebAuthn
   * specification requirements. WebAuthn requires canonical CBOR encoding with definite-length
   * maps and arrays (not indefinite-length).
   *
   * @return A configured ObjectMapper for CBOR encoding with definite-length encoding
   */
  private static ObjectMapper createCborMapper() {
    // Configure CBOR factory to use definite-length encoding (required by WebAuthn spec)
    // By default, Jackson writes definite-length maps when it can determine the size upfront
    CBORFactory cborFactory =
        new CBORFactory()
            .disable(com.fasterxml.jackson.dataformat.cbor.CBORGenerator.Feature.WRITE_TYPE_HEADER);
    ObjectMapper mapper = new ObjectMapper(cborFactory);
    // Ensure we write minimal integers for compact encoding
    mapper.enable(com.fasterxml.jackson.core.JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN);
    return mapper;
  }

  /** Builder class for YubiKeyEmulator with proper initialization and validation. */
  public static class YubiKeyEmulatorBuilder {
    /**
     * Builds and initializes a YubiKeyEmulator instance.
     *
     * <p>This method constructs the emulator and automatically initializes it by generating
     * attestation keys and certificates if they were not explicitly provided during configuration.
     *
     * @return a fully initialized YubiKeyEmulator instance
     * @throws CryptoException if cryptographic operations fail during initialization
     */
    public YubiKeyEmulator build() throws CryptoException {
      YubiKeyEmulator res = buildInternal();
      res.init();
      return res;
    }
  }

  /**
   * Initializes the emulator by generating attestation keys and certificate if not provided.
   *
   * @throws CryptoException If cryptographic operations fail
   */
  private void init() throws CryptoException {
    try {
      if (attestationKeyPair == null) {
        attestationKeyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
      }
      if (attestationCertificate == null) {
        attestationCertificate =
            CryptoUtils.generateAttestationCertificate(attestationKeyPair, attestationSubject);
      }
    } catch (Exception e) {
      throw new CryptoException("Failed to initialize attestation key pair and certificate", e);
    }
  }

  /**
   * Validates that the AAGUID is properly formatted.
   *
   * @throws InvalidConfigurationException If AAGUID is null or not a valid UUID
   */
  private void validateAAGUID() throws InvalidConfigurationException {
    if (aaguid == null || aaguid.isEmpty()) {
      throw new InvalidConfigurationException(
          "AAGUID must be specified for credential creation operations");
    }
    try {
      UUID.fromString(aaguid);
    } catch (IllegalArgumentException e) {
      throw new InvalidConfigurationException("AAGUID must be a valid UUID format: " + aaguid, e);
    }
  }

  /**
   * Creates a new credential from a JSON-encoded PublicKeyCredentialCreationOptions.
   *
   * @param json The JSON-encoded options
   * @return The created credential
   * @throws Exception If creation fails
   */
  public PublicKeyCredential<RegistrationResponse> create(String json) throws Exception {
    return create(jsonMapper.readValue(json, PublicKeyCredentialCreationOptions.class));
  }

  /**
   * Creates a new credential based on the provided options.
   *
   * @param options The credential creation options
   * @return The created credential with attestation
   * @throws InvalidConfigurationException If the emulator is not properly configured
   * @throws InvalidRequestException If the request cannot be satisfied by this authenticator
   * @throws CryptoException If cryptographic operations fail
   */
  public PublicKeyCredential<RegistrationResponse> create(
      PublicKeyCredentialCreationOptions options) throws Exception {
    validateAAGUID();

    if (supportedAttachmentTypes.isEmpty()) {
      throw new InvalidConfigurationException(
          "At least one authenticator attachment type must be supported");
    }

    if (!canAuthenticatorBeUsed(options.authenticatorSelection())) {
      throw new InvalidRequestException(
          "Authenticator does not meet the selection criteria specified in the request. "
              + "Check authenticator attachment, resident key, and user verification requirements.");
    }

    COSEAlgorithmIdentifier alg = findMatchingAlgorithm(options.pubKeyCredParams());
    if (alg == null) {
      throw new InvalidRequestException(
          "No matching algorithm found. Requested algorithms: "
              + options.pubKeyCredParams().stream()
                  .map(p -> p.alg().name())
                  .reduce((a, b) -> a + ", " + b)
                  .orElse("none")
              + ". Supported algorithms: "
              + supportedAlgorithms.stream()
                  .map(COSEAlgorithmIdentifier::name)
                  .reduce((a, b) -> a + ", " + b)
                  .orElse("none"));
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

    byte[] credentialId;
    KeyPair credentialKeyPair;
    byte[] credentialPublicKey;
    byte[] attestedCredentialData;

    try {
      credentialId = CryptoUtils.generateCredentialId();
      credentialKeyPair = CryptoUtils.generateKeyPair(alg);
      credentialPublicKey = CryptoUtils.encodeCOSEPublicKey(credentialKeyPair.getPublic(), alg);
      attestedCredentialData =
          CryptoUtils.createAttestedCredentialData(
              aaguidToBytes(), credentialId, credentialPublicKey);
    } catch (Exception e) {
      throw new CryptoException("Failed to generate credential key pair and attested data", e);
    }

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

    String clientDataJSON;
    byte[] clientDataHash;

    try {
      clientDataJSON = jsonMapper.writeValueAsString(clientData);
      clientDataHash =
          MessageDigest.getInstance("SHA-256")
              .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new CryptoException("Failed to generate client data hash", e);
    }

    AttestationObject attestationObject = generateAttestationObject(authData, clientDataHash);

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
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(encodeAttestationObject(attestationObject)),
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

  private byte[] aaguidToBytes() {
    UUID uuid = UUID.fromString(aaguid);
    ByteBuffer buffer = ByteBuffer.wrap(new byte[16]);
    buffer.putLong(uuid.getMostSignificantBits());
    buffer.putLong(uuid.getLeastSignificantBits());
    return buffer.array();
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

  /**
   * Gets (asserts) a credential from a JSON-encoded PublicKeyCredentialAssertionOptions.
   *
   * @param json The JSON-encoded options
   * @return The assertion response
   * @throws Exception If assertion fails
   */
  public PublicKeyCredential<AssertionResponse> get(String json) throws Exception {
    return get(jsonMapper.readValue(json, PublicKeyCredentialAssertionOptions.class));
  }

  /**
   * Gets (asserts) a credential based on the provided options.
   *
   * @param options The credential assertion options
   * @return The assertion response with signature
   * @throws CredentialNotFoundException If no matching credential is found
   * @throws CryptoException If cryptographic operations fail
   * @throws JsonProcessingException If json generation fails
   */
  public PublicKeyCredential<AssertionResponse> get(PublicKeyCredentialAssertionOptions options)
      throws CredentialNotFoundException, CryptoException, JsonProcessingException {
    StoredCredential credential = findMatchingCredential(options);

    if (credential == null) {
      String errorMsg =
          "No matching credential found for RP ID: "
              + options.rpId()
              + ". Total credentials stored: "
              + credentials.size();
      if (options.allowCredentials() != null && !options.allowCredentials().isEmpty()) {
        errorMsg +=
            ". Requested credential IDs: "
                + options.allowCredentials().stream()
                    .map(PublicKeyCredentialRef::id)
                    .reduce((a, b) -> a + ", " + b)
                    .orElse("none");
      }
      throw new CredentialNotFoundException(errorMsg);
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

    String clientDataJSON;
    byte[] clientDataHash;
    byte[] signature;

    try {
      clientDataJSON = jsonMapper.writeValueAsString(clientData);
      clientDataHash =
          MessageDigest.getInstance("SHA-256")
              .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));

      ByteArrayOutputStream sigData = new ByteArrayOutputStream();
      sigData.write(authData.encode());
      sigData.write(clientDataHash);

      signature =
          CryptoUtils.sign(
              sigData.toByteArray(), credential.keyPair().getPrivate(), credential.algorithm());
    } catch (Exception e) {
      throw new CryptoException("Failed to generate signature for assertion", e);
    }

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

  /**
   * Finds a matching credential for the given assertion options. Respects the order of
   * allowCredentials if specified.
   *
   * @param options The assertion options
   * @return The matching credential, or null if none found
   */
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

  /**
   * Removes a credential from storage.
   *
   * @param credentialId The base64url-encoded credential ID
   * @return true if the credential was found and removed, false otherwise
   */
  public boolean removeCredential(String credentialId) {
    return credentials.remove(credentialId) != null;
  }

  /**
   * Gets all credentials for a specific RP ID.
   *
   * @param rpId The relying party ID
   * @return List of credentials for the specified RP ID
   */
  public List<StoredCredential> getCredentialsByRpId(String rpId) {
    return credentials.values().stream().filter(cred -> cred.rpId().equals(rpId)).toList();
  }

  /**
   * Gets a specific credential by ID.
   *
   * @param credentialId The base64url-encoded credential ID
   * @return The credential, or null if not found
   */
  public StoredCredential getCredential(String credentialId) {
    return credentials.get(credentialId);
  }

  /**
   * Gets all stored credentials.
   *
   * @return Unmodifiable view of all credentials
   */
  public Map<String, StoredCredential> getAllCredentials() {
    return Map.copyOf(credentials);
  }

  /** Clears all stored credentials and resets the signature counter. */
  public void reset() {
    credentials.clear();
    signatureCounter = 0;
  }

  /**
   * Gets the total number of stored credentials.
   *
   * @return The credential count
   */
  public int getCredentialCount() {
    return credentials.size();
  }

  /**
   * Manually encodes attestation object to CBOR with definite-length encoding.
   *
   * <p>Jackson CBOR uses indefinite-length maps by default, which violates the WebAuthn spec
   * requirement for canonical CBOR. This method manually encodes the attestation object using
   * definite-length maps (0xAx prefix) instead of indefinite-length maps (0xBF prefix).
   *
   * @param attestationObject The attestation object to encode
   * @return CBOR-encoded bytes with definite-length maps
   * @throws Exception If encoding fails
   */
  private byte[] encodeAttestationObject(AttestationObject attestationObject) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Outer map: {fmt, authData, attStmt} = 3 items
    out.write(0xA3); // Map with 3 items (definite-length)

    // Key: "fmt" (3 chars)
    out.write(0x63); // Text string, 3 bytes
    out.write("fmt".getBytes(StandardCharsets.UTF_8));
    // Value: format string
    byte[] fmtBytes = attestationObject.fmt().getBytes(StandardCharsets.UTF_8);
    writeCBORTextString(out, fmtBytes);

    // Key: "authData"
    out.write(0x68); // Text string, 8 bytes
    out.write("authData".getBytes(StandardCharsets.UTF_8));
    // Value: auth data bytes
    byte[] authDataBytes = attestationObject.authData().encode();
    writeCBORByteString(out, authDataBytes);

    // Key: "attStmt"
    out.write(0x67); // Text string, 7 bytes
    out.write("attStmt".getBytes(StandardCharsets.UTF_8));
    // Value: attestation statement map
    writeAttStmtMap(out, attestationObject);

    return out.toByteArray();
  }

  private void writeAttStmtMap(ByteArrayOutputStream out, AttestationObject attestationObject)
      throws Exception {
    if (attestationObject.fmt().equals(AttestationFormat.NONE.getValue())) {
      // Empty map for "none" attestation
      out.write(0xA0); // Map with 0 items
      return;
    }

    // Count the number of fields in attStmt
    int fieldCount = 0;
    if (attestationObject.attStmt().sig() != null) fieldCount++;
    if (attestationObject.attStmt().x5c() != null
        && attestationObject.attStmt().x5c().length > 0) fieldCount++;
    if (attestationObject.attStmt().alg() != null) fieldCount++;

    // Write map header with field count
    out.write(0xA0 | fieldCount); // Map with fieldCount items

    // Write "alg" if present (write first for packed format)
    if (attestationObject.attStmt().alg() != null) {
      out.write(0x63); // Text string, 3 bytes
      out.write("alg".getBytes(StandardCharsets.UTF_8));
      writeCBORInt(out, attestationObject.attStmt().alg().getValue());
    }

    // Write "sig" if present
    if (attestationObject.attStmt().sig() != null) {
      out.write(0x63); // Text string, 3 bytes
      out.write("sig".getBytes(StandardCharsets.UTF_8));
      writeCBORByteString(out, attestationObject.attStmt().sig());
    }

    // Write "x5c" if present
    if (attestationObject.attStmt().x5c() != null
        && attestationObject.attStmt().x5c().length > 0) {
      out.write(0x63); // Text string, 3 bytes
      out.write("x5c".getBytes(StandardCharsets.UTF_8));
      // Write array of certificates
      out.write(0x80 | attestationObject.attStmt().x5c().length); // Array with length
      for (byte[] cert : attestationObject.attStmt().x5c()) {
        writeCBORByteString(out, cert);
      }
    }
  }

  private void writeCBORTextString(ByteArrayOutputStream out, byte[] bytes) throws Exception {
    if (bytes.length < 24) {
      out.write(0x60 | bytes.length);
    } else if (bytes.length < 256) {
      out.write(0x78);
      out.write(bytes.length);
    } else {
      out.write(0x79);
      out.write((bytes.length >> 8) & 0xFF);
      out.write(bytes.length & 0xFF);
    }
    out.write(bytes);
  }

  private void writeCBORByteString(ByteArrayOutputStream out, byte[] bytes) throws Exception {
    if (bytes.length < 24) {
      out.write(0x40 | bytes.length);
    } else if (bytes.length < 256) {
      out.write(0x58);
      out.write(bytes.length);
    } else {
      out.write(0x59);
      out.write((bytes.length >> 8) & 0xFF);
      out.write(bytes.length & 0xFF);
    }
    out.write(bytes);
  }

  private void writeCBORInt(ByteArrayOutputStream out, int value) throws Exception {
    if (value >= 0 && value < 24) {
      out.write(value);
    } else if (value >= 0 && value < 256) {
      out.write(0x18);
      out.write(value);
    } else if (value >= -24 && value < 0) {
      out.write(0x20 | (-1 - value));
    } else if (value < 0 && value >= -256) {
      out.write(0x38);
      out.write(-1 - value);
    } else if (value >= 0) {
      out.write(0x19);
      out.write((value >> 8) & 0xFF);
      out.write(value & 0xFF);
    } else {
      out.write(0x39);
      int absValue = -1 - value;
      out.write((absValue >> 8) & 0xFF);
      out.write(absValue & 0xFF);
    }
  }

  private byte[] getExtensionBytes(Integer credentialProtectionPolicy)
      throws JsonProcessingException {
    byte[] extensionsBytes = null;
    if (supportsCredProtect && credentialProtectionPolicy != null) {
      // Use LinkedHashMap to ensure definite-length CBOR encoding
      Map<String, Object> extensionsMap = new java.util.LinkedHashMap<>();
      extensionsMap.put("credProtect", credentialProtectionPolicy);
      extensionsBytes = cborMapper.writeValueAsBytes(extensionsMap);
    }
    return extensionsBytes;
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

  /**
   * Generates an attestation object based on the configured attestation format.
   *
   * @param authData The authenticator data
   * @param clientDataHash The SHA-256 hash of the client data JSON
   * @return The attestation object
   * @throws CryptoException If cryptographic operations fail
   */
  private AttestationObject generateAttestationObject(
      AuthenticatorData authData, byte[] clientDataHash) throws CryptoException {
    try {
      return switch (attestationFormat) {
        case NONE -> generateNoneAttestation(authData);
        case FIDO_U2F -> generateFidoU2fAttestation(authData, clientDataHash);
        case PACKED -> generatePackedAttestation(authData, clientDataHash);
        default -> throw new CryptoException(
            "Unsupported attestation format: " + attestationFormat.getValue());
      };
    } catch (Exception e) {
      throw new CryptoException("Failed to generate attestation object", e);
    }
  }

  /**
   * Generates a "none" attestation - no attestation statement.
   *
   * @param authData The authenticator data
   * @return The attestation object with empty attestation statement
   */
  private AttestationObject generateNoneAttestation(AuthenticatorData authData) {
    // For "none" attestation, the attStmt is an empty map
    AttestationStatement attStmt = new AttestationStatement(null, null, null);
    return new AttestationObject(AttestationFormat.NONE.getValue(), authData, attStmt);
  }

  /**
   * Generates a "packed" attestation statement.
   *
   * @param authData The authenticator data
   * @param clientDataHash The SHA-256 hash of the client data JSON
   * @return The attestation object with packed attestation
   * @throws Exception If cryptographic operations fail
   */
  private AttestationObject generatePackedAttestation(
      AuthenticatorData authData, byte[] clientDataHash) throws Exception {
    ByteArrayOutputStream sigData = new ByteArrayOutputStream();
    sigData.write(authData.encode());
    sigData.write(clientDataHash);

    byte[] signature =
        CryptoUtils.sign(
            sigData.toByteArray(), attestationKeyPair.getPrivate(), COSEAlgorithmIdentifier.ES256);

    AttestationStatement attStmt =
        new AttestationStatement(
            signature,
            new byte[][] {attestationCertificate.getEncoded()},
            COSEAlgorithmIdentifier.ES256);

    return new AttestationObject(AttestationFormat.PACKED.getValue(), authData, attStmt);
  }

  /**
   * Generates a "fido-u2f" attestation statement. FIDO U2F format uses a specific signature format
   * and requires ES256 algorithm. The public key in FIDO U2F must be in raw format (65 bytes: 0x04
   * || X || Y), not COSE format.
   *
   * @param authData The authenticator data
   * @param clientDataHash The SHA-256 hash of the client data JSON
   * @return The attestation object with fido-u2f attestation
   * @throws Exception If cryptographic operations fail
   */
  private AttestationObject generateFidoU2fAttestation(
      AuthenticatorData authData, byte[] clientDataHash) throws Exception {
    // FIDO U2F attestation format requires a specific signature format
    // Format: 0x00 || rpIdHash || clientDataHash || credentialId || credentialPublicKeyU2F
    byte[] authDataBytes = authData.encode();

    // Extract components from authenticator data
    // rpIdHash: bytes 0-31 (32 bytes)
    byte[] rpIdHash = Arrays.copyOfRange(authDataBytes, 0, 32);

    // For FIDO U2F, we need to extract the credential ID and public key from attested credential
    // data
    // attested credential data starts at byte 37 (after rpIdHash + flags + counter)
    int attestedCredentialDataStart = 37;
    // Skip AAGUID (16 bytes)
    int credIdLengthStart = attestedCredentialDataStart + 16;

    // Read credential ID length (2 bytes, big-endian)
    int credIdLength =
        ((authDataBytes[credIdLengthStart] & 0xFF) << 8)
            | (authDataBytes[credIdLengthStart + 1] & 0xFF);
    int credIdStart = credIdLengthStart + 2;
    byte[] credentialId =
        Arrays.copyOfRange(authDataBytes, credIdStart, credIdStart + credIdLength);

    // Public key starts after credential ID - it's in COSE format currently
    int publicKeyStart = credIdStart + credIdLength;

    // Extract only the COSE public key CBOR value (not including any following extensions)
    // This uses a CBOR parser to determine the exact length of the COSE key structure
    byte[] credentialPublicKeyCOSE = CryptoUtils.extractCborValue(authDataBytes, publicKeyStart);

    // FIDO U2F requires the public key in raw format: 0x04 || X || Y
    // We need to extract X and Y from the COSE public key and convert to U2F format
    byte[] credentialPublicKeyU2F = CryptoUtils.cosePublicKeyToU2F(credentialPublicKeyCOSE);

    // Build verification data for signature
    ByteArrayOutputStream verificationData = new ByteArrayOutputStream();
    verificationData.write(0x00); // Reserved byte
    verificationData.write(rpIdHash);
    verificationData.write(clientDataHash);
    verificationData.write(credentialId);
    verificationData.write(credentialPublicKeyU2F);

    byte[] signature =
        CryptoUtils.sign(
            verificationData.toByteArray(),
            attestationKeyPair.getPrivate(),
            COSEAlgorithmIdentifier.ES256);

    AttestationStatement attStmt =
        new AttestationStatement(
            signature, new byte[][] {attestationCertificate.getEncoded()}, null);

    return new AttestationObject(AttestationFormat.FIDO_U2F.getValue(), authData, attStmt);
  }
}
