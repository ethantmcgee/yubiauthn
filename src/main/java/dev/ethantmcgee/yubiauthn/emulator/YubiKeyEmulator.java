package dev.ethantmcgee.yubiauthn.emulator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.model.*;
import dev.ethantmcgee.yubiauthn.model.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Emulator for YubiKey NFC 5C authenticator.
 * Implements FIDO2/WebAuthn credential creation and assertion.
 */
public class YubiKeyEmulator {

    // YubiKey 5 Series AAGUID (Authenticator Attestation GUID)
    private static final byte[] YUBIKEY_5_AAGUID = new byte[]{
        (byte) 0x2f, (byte) 0xc0, (byte) 0x57, (byte) 0x9f,
        (byte) 0x81, (byte) 0x13, (byte) 0x47, (byte) 0xea,
        (byte) 0xb1, (byte) 0x16, (byte) 0xbb, (byte) 0x5a,
        (byte) 0x8d, (byte) 0xb9, (byte) 0x20, (byte) 0x2a
    };

    private final Map<String, StoredCredential> credentials = new HashMap<>();
    private final KeyPair attestationKeyPair;
    private final X509Certificate attestationCertificate;
    private int signatureCounter = 0;
    private final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());

    /**
     * Stored credential information.
     */
    private record StoredCredential(
        byte[] credentialId,
        KeyPair keyPair,
        COSEAlgorithmIdentifier algorithm,
        String rpId,
        byte[] userHandle,
        int signCount
    ) {}

    public YubiKeyEmulator() throws Exception {
        // Generate attestation key pair and certificate (simulating factory provisioning)
        this.attestationKeyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
        this.attestationCertificate = CryptoUtils.generateAttestationCertificate(
            attestationKeyPair,
            "CN=YubiKey NFC 5C,OU=Authenticator Attestation,O=Yubico,C=SE"
        );
    }

    /**
     * Creates a new WebAuthn credential (registration).
     *
     * @param options The credential creation options from the relying party
     * @return A PublicKeyCredential containing the attestation response
     */
    public PublicKeyCredential<AuthenticatorAttestationResponse> makeCredential(
        PublicKeyCredentialCreationOptions options) throws Exception {

        // Select the first supported algorithm
        COSEAlgorithmIdentifier selectedAlgorithm = options.pubKeyCredParams().stream()
            .map(PublicKeyCredentialParameters::alg)
            .filter(alg -> alg == COSEAlgorithmIdentifier.ES256 ||
                          alg == COSEAlgorithmIdentifier.ES384 ||
                          alg == COSEAlgorithmIdentifier.ES512)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("No supported algorithm found"));

        // Generate credential key pair
        KeyPair credentialKeyPair = CryptoUtils.generateKeyPair(selectedAlgorithm);

        // Generate credential ID
        byte[] credentialId = CryptoUtils.generateCredentialId();

        // Encode credential public key in COSE format
        byte[] credentialPublicKey = CryptoUtils.encodeCOSEPublicKey(
            credentialKeyPair.getPublic(),
            selectedAlgorithm
        );

        // Create attested credential data
        byte[] attestedCredentialData = CryptoUtils.createAttestedCredentialData(
            YUBIKEY_5_AAGUID,
            credentialId,
            credentialPublicKey
        );

        // Create authenticator data
        String rpId = options.rp().id() != null ? options.rp().id() : "localhost";
        AuthenticatorData authData = new AuthenticatorData.Builder()
            .rpId(rpId)
            .userPresent(true)
            .userVerified(options.authenticatorSelection() != null &&
                         options.authenticatorSelection().userVerification() == UserVerificationRequirement.REQUIRED)
            .attestedCredentialData(attestedCredentialData)
            .signCount(signatureCounter++)
            .build();

        // Create client data JSON
        Map<String, Object> clientData = new HashMap<>();
        clientData.put("type", "webauthn.create");
        clientData.put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(options.challenge()));
        clientData.put("origin", "https://" + rpId);
        clientData.put("crossOrigin", false);

        String clientDataJSON = new ObjectMapper().writeValueAsString(clientData);
        byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
            .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));

        // Create attestation signature
        ByteArrayOutputStream sigData = new ByteArrayOutputStream();
        sigData.write(authData.encode());
        sigData.write(clientDataHash);

        byte[] signature = CryptoUtils.sign(
            sigData.toByteArray(),
            attestationKeyPair.getPrivate(),
            COSEAlgorithmIdentifier.ES256
        );

        // Create attestation statement
        AttestationObject.AttestationStatement attStmt = new AttestationObject.AttestationStatement(
            signature,
            new byte[][]{attestationCertificate.getEncoded()},
            COSEAlgorithmIdentifier.ES256
        );

        // Create attestation object
        AttestationObject attestationObject = new AttestationObject(
            "packed",
            authData,
            attStmt
        );

        // Encode attestation object in CBOR
        byte[] attestationObjectBytes = encodeAttestationObject(attestationObject);

        // Store credential
        String credentialKey = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
        credentials.put(credentialKey, new StoredCredential(
            credentialId,
            credentialKeyPair,
            selectedAlgorithm,
            rpId,
            options.user().id(),
            signatureCounter
        ));

        // Create response
        AuthenticatorAttestationResponse response = new AuthenticatorAttestationResponse(
            clientDataJSON.getBytes(StandardCharsets.UTF_8),
            attestationObjectBytes,
            new AuthenticatorTransport[]{AuthenticatorTransport.NFC, AuthenticatorTransport.USB}
        );

        return new PublicKeyCredential<>(
            credentialId,
            PublicKeyCredentialType.PUBLIC_KEY.getValue(),
            credentialId,
            response,
            PublicKeyCredential.AuthenticatorAttachment.CROSS_PLATFORM
        );
    }

    /**
     * Performs authentication with an existing credential (assertion).
     *
     * @param options The credential request options from the relying party
     * @return A PublicKeyCredential containing the assertion response
     */
    public PublicKeyCredential<AuthenticatorAssertionResponse> getAssertion(
        PublicKeyCredentialRequestOptions options) throws Exception {

        // Find a matching credential
        StoredCredential credential = null;
        byte[] credentialIdToUse = null;

        if (options.allowCredentials() != null && !options.allowCredentials().isEmpty()) {
            for (PublicKeyCredentialDescriptor descriptor : options.allowCredentials()) {
                String key = Base64.getUrlEncoder().withoutPadding().encodeToString(descriptor.id());
                if (credentials.containsKey(key)) {
                    credential = credentials.get(key);
                    credentialIdToUse = descriptor.id();
                    break;
                }
            }
        } else {
            // If no specific credentials requested, use any credential for this RP
            String rpId = options.rpId();
            for (Map.Entry<String, StoredCredential> entry : credentials.entrySet()) {
                if (entry.getValue().rpId.equals(rpId)) {
                    credential = entry.getValue();
                    credentialIdToUse = entry.getValue().credentialId;
                    break;
                }
            }
        }

        if (credential == null) {
            throw new IllegalArgumentException("No matching credential found");
        }

        // Create authenticator data
        AuthenticatorData authData = new AuthenticatorData.Builder()
            .rpId(credential.rpId)
            .userPresent(true)
            .userVerified(options.userVerification() == UserVerificationRequirement.REQUIRED)
            .signCount(signatureCounter++)
            .build();

        // Create client data JSON
        Map<String, Object> clientData = new HashMap<>();
        clientData.put("type", "webauthn.get");
        clientData.put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(options.challenge()));
        clientData.put("origin", "https://" + credential.rpId);
        clientData.put("crossOrigin", false);

        String clientDataJSON = new ObjectMapper().writeValueAsString(clientData);
        byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
            .digest(clientDataJSON.getBytes(StandardCharsets.UTF_8));

        // Create assertion signature
        ByteArrayOutputStream sigData = new ByteArrayOutputStream();
        sigData.write(authData.encode());
        sigData.write(clientDataHash);

        byte[] signature = CryptoUtils.sign(
            sigData.toByteArray(),
            credential.keyPair.getPrivate(),
            credential.algorithm
        );

        // Update stored credential's sign count
        String credentialKey = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialIdToUse);
        credentials.put(credentialKey, new StoredCredential(
            credential.credentialId,
            credential.keyPair,
            credential.algorithm,
            credential.rpId,
            credential.userHandle,
            signatureCounter
        ));

        // Create response
        AuthenticatorAssertionResponse response = new AuthenticatorAssertionResponse(
            clientDataJSON.getBytes(StandardCharsets.UTF_8),
            authData.encode(),
            signature,
            credential.userHandle
        );

        return new PublicKeyCredential<>(
            credentialIdToUse,
            PublicKeyCredentialType.PUBLIC_KEY.getValue(),
            credentialIdToUse,
            response,
            PublicKeyCredential.AuthenticatorAttachment.CROSS_PLATFORM
        );
    }

    /**
     * Encodes an attestation object in CBOR format.
     */
    private byte[] encodeAttestationObject(AttestationObject attestationObject) throws Exception {
        Map<String, Object> attestationMap = new HashMap<>();
        attestationMap.put("fmt", attestationObject.fmt());
        attestationMap.put("authData", attestationObject.authData().encode());

        Map<String, Object> attStmtMap = new HashMap<>();
        attStmtMap.put("alg", attestationObject.attStmt().alg().getValue());
        attStmtMap.put("sig", attestationObject.attStmt().sig());

        if (attestationObject.attStmt().x5c() != null && attestationObject.attStmt().x5c().length > 0) {
            attStmtMap.put("x5c", Arrays.asList(attestationObject.attStmt().x5c()));
        }

        attestationMap.put("attStmt", attStmtMap);

        return cborMapper.writeValueAsBytes(attestationMap);
    }

    /**
     * Gets the number of stored credentials.
     */
    public int getCredentialCount() {
        return credentials.size();
    }

    /**
     * Clears all stored credentials (for testing).
     */
    public void clearCredentials() {
        credentials.clear();
        signatureCounter = 0;
    }

    /**
     * Gets the AAGUID of this authenticator.
     */
    public byte[] getAAGUID() {
        return YUBIKEY_5_AAGUID.clone();
    }
}
