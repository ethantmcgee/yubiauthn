# YubiAuthn

A Java 21 library that emulates a YubiKey NFC 5C hardware authenticator, providing FIDO2/WebAuthn credential creation and attestation functionality for testing and development purposes.

## Requirements

- Java 21 or higher
- Maven 3.6+ (for building)

## Installation

### Maven

```xml
<dependency>
    <groupId>dev.ethantmcgee</groupId>
    <artifactId>yubiauthn</artifactId>
    <version>1.0.1</version>
</dependency>
```

### Building from Source

```bash
git clone https://github.com/ethantmcgee/yubiauthn.git
cd yubiauthn
mvn clean install
```

## Features

- **Multiple Authenticator Models**: Pre-configured YubiKey 5 Series emulators
- **COSE Algorithm Support**: ES256, ES384, ES512, RS256, RS384, RS512, EdDSA
- **Authenticator Types**: Cross-platform and platform authenticators
- **User Verification**: Configurable user presence and user verification
- **Resident Keys**: Support for discoverable credentials
- **Extensions**: credProtect, credProps, minPinLength
- **Backup Flags**: Backup eligible and backup state support
- **Attestation**: Self-signed packed attestation format
- **Credential Management**: Full CRUD operations for stored credentials
- **Custom Exceptions**: Specific exception types for better error handling

## Usage

### Basic Example

```java
import dev.ethantmcgee.yubiauthn.emulator.Yubikey;
import dev.ethantmcgee.yubiauthn.emulator.YubiKeyEmulator;

// Create an emulator instance using a pre-configured model
YubiKeyEmulator emulator = Yubikey.get5cNfc();

// Register a credential
PublicKeyCredentialCreationOptions registrationOptions = // ... build options
PublicKeyCredential<RegistrationResponse> credential = emulator.create(registrationOptions);

// Authenticate with the credential
PublicKeyCredentialAssertionOptions assertionOptions = // ... build options
PublicKeyCredential<AssertionResponse> assertion = emulator.get(assertionOptions);
```

### Custom Emulator Configuration

```java
YubiKeyEmulator customEmulator = YubiKeyEmulator.builder()
    .aaguid("2fc0579f-8113-47ea-b116-bb5a8db9202a")
    .description("Custom Authenticator")
    .transports(List.of(TransportType.USB, TransportType.NFC))
    .supportedAlgorithms(List.of(
        COSEAlgorithmIdentifier.ES256,
        COSEAlgorithmIdentifier.ES384
    ))
    .supportedAttachmentTypes(List.of(AuthenticatorAttachmentType.CROSS_PLATFORM))
    .supportsUserPresence(true)
    .supportsUserVerification(true)
    .supportsResidentKey(true)
    .supportsCredProtect(true)
    .supportsMinPinLength(true)
    .pinLength(6)
    .backupEligible(true)
    .backupState(false)
    .build();
```

### Credential Management

```java
// Get total credential count
int count = emulator.getCredentialCount();

// Get all credentials for a specific RP
List<StoredCredential> credentials = emulator.getCredentialsByRpId("example.com");

// Get a specific credential
StoredCredential cred = emulator.getCredential(credentialId);

// Remove a credential
boolean removed = emulator.removeCredential(credentialId);

// Clear all credentials and reset state
emulator.reset();

// Get current signature counter
int counter = emulator.getSignatureCounter();
```

### Error Handling

```java
import dev.ethantmcgee.yubiauthn.exception.*;

try {
    PublicKeyCredential<RegistrationResponse> credential =
        emulator.create(registrationOptions);
} catch (InvalidConfigurationException e) {
    // Emulator is not properly configured (e.g., missing AAGUID)
    System.err.println("Configuration error: " + e.getMessage());
} catch (InvalidRequestException e) {
    // Request doesn't meet authenticator requirements
    // (e.g., no matching algorithms, wrong authenticator type)
    System.err.println("Request error: " + e.getMessage());
} catch (CryptoException e) {
    // Cryptographic operation failed
    System.err.println("Crypto error: " + e.getMessage());
}

try {
    PublicKeyCredential<AssertionResponse> assertion =
        emulator.get(assertionOptions);
} catch (CredentialNotFoundException e) {
    // No matching credential found for the request
    System.err.println("Credential not found: " + e.getMessage());
} catch (CryptoException e) {
    System.err.println("Crypto error: " + e.getMessage());
}
```

### Integration with WebAuthn Libraries

This emulator works seamlessly with popular WebAuthn server libraries like [java-webauthn-server](https://github.com/Yubico/java-webauthn-server):

```java
import com.yubico.webauthn.*;

// Initialize emulator
YubiKeyEmulator emulator = Yubikey.get5cNfc();

// Set up relying party
RelyingParty rp = RelyingParty.builder()
    .identity(RelyingPartyIdentity.builder()
        .id("example.com")
        .name("Example Company")
        .build())
    .credentialRepository(credentialStore)
    .build();

// Start registration
PublicKeyCredentialCreationOptions creationOptions =
    rp.startRegistration(StartRegistrationOptions.builder()
        .user(UserIdentity.builder()
            .name("user@example.com")
            .displayName("User Name")
            .id(userId)
            .build())
        .build());

// Emulator creates credential
PublicKeyCredential credential = emulator.create(creationOptions.toJson());

// Finish registration with relying party
RegistrationResult result = rp.finishRegistration(
    FinishRegistrationOptions.builder()
        .request(creationOptions)
        .response(credential)
        .build());
```

For complete examples, see [tests](src/test/java/dev/ethantmcgee/yubiauthn/JavaWebauthnServerIntegrationTest.java).

## Limitations

This emulator has the following limitations compared to real YubiKey hardware:

- **Attestation Format**: Only supports "packed" attestation format (not FIDO U2F format)
- **Storage**: Credentials are stored in memory only and are not persisted
- **Thread Safety**: Not thread-safe for concurrent write operations
- **User Interaction**: No actual user presence verification or biometric authentication
- **Attestation Chain**: Uses self-signed certificates, not production attestation chains
- **Credential IDs**: Fixed 16-byte credential IDs (real YubiKeys may vary)
- **Certificate Validity**: Generated certificates have 1-year validity
- **Algorithm Support in COSE Encoding**: Currently only EC keys are supported in COSE encoding (EdDSA and RSA support planned)

## Architecture

The emulator consists of several key components:

- **YubiKeyEmulator**: Main emulator class that handles credential operations
- **CryptoUtils**: Cryptographic utilities for key generation, signing, and COSE encoding
- **Model Classes**: Data classes representing WebAuthn structures (PublicKeyCredential, AuthenticatorData, etc.)
- **Exceptions**: Specific exception types for different error scenarios
- **Yubikey**: Pre-configured emulator builders for common YubiKey models

### Exception Hierarchy

```
AuthenticatorException (base)
├── InvalidConfigurationException (emulator misconfiguration)
├── InvalidRequestException (request doesn't meet requirements)
├── CredentialNotFoundException (credential not found)
└── CryptoException (cryptographic operation failure)
```

### Supported Algorithms

| Algorithm | COSE Identifier | Description |
|-----------|-----------------|-------------|
| ES256 | -7 | ECDSA with SHA-256 (P-256 curve) |
| EdDSA | -8 | Edwards-curve Digital Signature Algorithm |
| ES384 | -35 | ECDSA with SHA-384 (P-384 curve) |
| ES512 | -36 | ECDSA with SHA-512 (P-521 curve) |
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 |

## Testing

Run the test suite:

```bash
mvn test
```

## Security Considerations

This library is intended for **testing and development purposes only**. It should not be used in production environments as a replacement for real hardware authenticators.

## Contributing

Please read [CONTRIBUTING.md](https://github.com/ethantmcgee/yubiauthn/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors

* **Ethan McGee** - *Initial work* - [ethantmcgee](https://github.com/ethantmcgee)

See also the list of [contributors](https://github.com/ethantmcgee/yubiauthn/contributors) who participated in this project.

## Inspired By

This library is a successor of [softauthn](https://github.com/adessoSE/softauthn).

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/ethantmcgee/yubiauthn/blob/main/LICENSE.md) file for details.
