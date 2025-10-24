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
    <version>1.0.4</version>
</dependency>
```

### Building from Source

```bash
git clone https://github.com/ethantmcgee/yubiauthn.git
cd yubiauthn
mvn clean install
```

## Features

- **COSE Algorithm Support**: ES256, ES384, ES512, RS256, RS384, RS512, EdDSA
- **Authenticator Types**: Cross-platform and platform authenticators
- **User Verification**: Configurable user presence and user verification
- **Resident Keys**: Support for discoverable credentials
- **Extensions**: credProtect, credProps, minPinLength
- **Backup Flags**: Backup eligible and backup state support
- **Attestation**: Self-signed packed attestation format

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
