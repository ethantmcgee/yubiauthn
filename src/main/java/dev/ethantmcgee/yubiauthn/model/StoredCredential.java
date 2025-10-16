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
 *
 * @param credentialId The unique identifier for this credential
 * @param keyPair The public/private key pair for this credential
 * @param algorithm The COSE algorithm identifier used for this credential
 * @param rpId The relying party identifier for this credential
 * @param userHandle The user handle (user ID) associated with this credential
 * @param signCount The signature counter value for this credential
 * @param rk Whether this is a resident key (discoverable credential)
 * @param credentialProtectionPolicy The credential protection policy level, if set
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
