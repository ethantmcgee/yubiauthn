package dev.ethantmcgee.yubiauthn.model;

import java.security.KeyPair;

/**
 * Represents a credential stored by the authenticator.
 *
 * <p>This is an internal representation of a WebAuthn credential as stored within an authenticator
 * or emulator. It contains the credential ID, key pair, algorithm, and related metadata needed for
 * authentication operations.
 *
 * <p>This is not directly specified in the WebAuthn specification but represents the internal state
 * that an authenticator maintains for each credential.
 */
public record StoredCredential(
    byte[] credentialId,
    KeyPair keyPair,
    COSEAlgorithmIdentifier algorithm,
    String rpId,
    String userHandle,
    int signCount,
    boolean rk,
    Integer credentialProtectionPolicy) {}
