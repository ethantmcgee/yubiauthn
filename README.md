# YubiAuthn

A Java 24 library that emulates a YubiKey NFC 5C hardware authenticator, providing FIDO2/WebAuthn credential creation and attestation functionality for testing and development purposes.

## Requirements

- Java 24 or higher
- Maven 3.6+ (for building)

## Installation

### Maven

```xml
<dependency>
    <groupId>dev.ethantmcgee</groupId>
    <artifactId>yubiauthn</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Building from Source

```bash
git clone https://github.com/ethantmcgee/yubiauthn.git
cd yubiauthn
mvn clean install
```

## Usage

### Creating a Credential (Registration)

```java
import dev.ethantmcgee.yubiauthn.emulator.YubiKeyEmulator;
import dev.ethantmcgee.yubiauthn.model.*;
import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;

// Initialize the emulator
YubiKeyEmulator emulator = new YubiKeyEmulator();

// Create credential creation options
PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
    new PublicKeyCredentialRpEntity("example.com", "Example Corp"),
    new PublicKeyCredentialUserEntity(
        "user123".getBytes(),
        "user@example.com",
        "John Doe"
    ),
    CryptoUtils.generateChallenge(),
    List.of(
        new PublicKeyCredentialParameters(
            PublicKeyCredentialType.PUBLIC_KEY,
            COSEAlgorithmIdentifier.ES256
        )
    ),
    30000L,
    null,
    new AuthenticatorSelectionCriteria(
        AuthenticatorSelectionCriteria.AuthenticatorAttachment.CROSS_PLATFORM,
        false,
        "discouraged",
        UserVerificationRequirement.PREFERRED
    ),
    AttestationConveyancePreference.DIRECT
);

// Create the credential
PublicKeyCredential<AuthenticatorAttestationResponse> credential =
    emulator.makeCredential(options);

// The credential contains:
// - credential.id(): The credential ID
// - credential.response().attestationObject(): The attestation object with signature
// - credential.response().clientDataJSON(): The client data JSON
```

### Authenticating with a Credential (Assertion)

```java
// Create authentication options
PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
    CryptoUtils.generateChallenge(),
    30000L,
    "example.com",
    List.of(
        new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credentialId, // From the credential created above
            List.of(AuthenticatorTransport.USB, AuthenticatorTransport.NFC)
        )
    ),
    UserVerificationRequirement.PREFERRED
);

// Get assertion
PublicKeyCredential<AuthenticatorAssertionResponse> assertion =
    emulator.getAssertion(requestOptions);

// The assertion contains:
// - assertion.response().authenticatorData(): Authenticator data with signature counter
// - assertion.response().signature(): The cryptographic signature
// - assertion.response().userHandle(): The user identifier
// - assertion.response().clientDataJSON(): The client data JSON
```

### Complete Example

```java
import dev.ethantmcgee.yubiauthn.emulator.YubiKeyEmulator;
import dev.ethantmcgee.yubiauthn.model.*;
import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import java.util.List;

public class WebAuthnExample {
    public static void main(String[] args) throws Exception {
        // Initialize emulator
        YubiKeyEmulator emulator = new YubiKeyEmulator();

        // Registration
        byte[] userId = "user12345".getBytes();
        PublicKeyCredentialCreationOptions createOptions =
            new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity("myapp.com", "My Application"),
                new PublicKeyCredentialUserEntity(userId, "alice@example.com", "Alice"),
                CryptoUtils.generateChallenge(),
                List.of(new PublicKeyCredentialParameters(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    COSEAlgorithmIdentifier.ES256
                )),
                30000L,
                null,
                null,
                AttestationConveyancePreference.NONE
            );

        PublicKeyCredential<AuthenticatorAttestationResponse> credential =
            emulator.makeCredential(createOptions);

        System.out.println("Credential created with ID: " +
            java.util.Base64.getUrlEncoder().encodeToString(credential.id()));

        // Authentication
        PublicKeyCredentialRequestOptions assertionOptions =
            new PublicKeyCredentialRequestOptions(
                CryptoUtils.generateChallenge(),
                30000L,
                "myapp.com",
                List.of(new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    credential.rawId(),
                    null
                )),
                UserVerificationRequirement.PREFERRED
            );

        PublicKeyCredential<AuthenticatorAssertionResponse> assertion =
            emulator.getAssertion(assertionOptions);

        System.out.println("Authentication successful!");
        System.out.println("User handle: " +
            new String(assertion.response().userHandle()));
    }
}
```

## Architecture

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

## Versioning

We use daily versions in the format YYYY.MM.DD.

## Authors

* **Ethan McGee** - *Initial work* - [ethantmcgee](https://github.com/ethantmcgee)

See also the list of [contributors](https://github.com/ethantmcgee/yubiauthn/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/ethantmcgee/yubiauthn/blob/main/LICENSE.md) file for details.
