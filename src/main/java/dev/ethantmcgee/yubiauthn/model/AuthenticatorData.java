package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.annotation.JsonValue;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import lombok.Getter;

/**
 * Represents the authenticator data structure used in WebAuthn ceremonies.
 *
 * <p>This class models the authenticator data structure defined in the Web Authentication API. It
 * contains information about the authenticator's state, including the RP ID hash, flags indicating
 * various states (user presence, user verification, etc.), signature counter, and optional attested
 * credential data and extensions.
 *
 * <p>The flags byte contains the following bits:
 *
 * <ul>
 *   <li>UP (0x01): User Present
 *   <li>UV (0x04): User Verified
 *   <li>BE (0x08): Backup Eligible
 *   <li>BS (0x10): Backup State
 *   <li>AT (0x40): Attested Credential Data included
 *   <li>ED (0x80): Extension Data included
 * </ul>
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data">MDN
 *     - Authenticator Data</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">W3C WebAuthn - Authenticator
 *     Data</a>
 */
@Getter
public class AuthenticatorData {
  private static final int FLAG_UP = 0x01; // User Present
  private static final int FLAG_UV = 0x04; // User Verified
  private static final int FLAG_BE = 0x08; // Backup Eligible
  private static final int FLAG_BS = 0x10; // Backup State
  private static final int FLAG_AT = 0x40; // Attested Credential Data included
  private static final int FLAG_ED = 0x80; // Extension Data included

  private final byte[] rpIdHash;
  private final byte flags;
  private final int signCount;
  private final byte[] attestedCredentialData;
  private final byte[] extensions;

  /**
   * Constructs an AuthenticatorData instance with the specified parameters.
   *
   * @param rpIdHash the SHA-256 hash of the Relying Party ID (must be exactly 32 bytes)
   * @param flags the flags byte indicating various authenticator states
   * @param signCount the signature counter value
   * @param attestedCredentialData optional attested credential data (may be null)
   * @param extensions optional extension data (may be null)
   * @throws IllegalArgumentException if rpIdHash is null or not 32 bytes
   */
  public AuthenticatorData(
      byte[] rpIdHash,
      byte flags,
      int signCount,
      byte[] attestedCredentialData,
      byte[] extensions) {
    if (rpIdHash == null || rpIdHash.length != 32) {
      throw new IllegalArgumentException("RP ID hash must be 32 bytes");
    }
    this.rpIdHash = rpIdHash;
    this.flags = flags;
    this.signCount = signCount;
    this.attestedCredentialData = attestedCredentialData;
    this.extensions = extensions;
  }

  /**
   * Encodes the authenticator data into its binary representation.
   *
   * <p>The encoded data consists of:
   *
   * <ul>
   *   <li>32 bytes: RP ID hash
   *   <li>1 byte: flags
   *   <li>4 bytes: signature counter (big-endian)
   *   <li>Variable: attested credential data (if present)
   *   <li>Variable: extensions (if present)
   * </ul>
   *
   * @return the binary encoded authenticator data
   */
  public byte[] encode() {
    int size = 32 + 1 + 4; // rpIdHash + flags + signCount
    if (attestedCredentialData != null) {
      size += attestedCredentialData.length;
    }
    if (extensions != null) {
      size += extensions.length;
    }

    ByteBuffer buffer = ByteBuffer.allocate(size);
    buffer.put(rpIdHash);
    buffer.put(flags);
    buffer.putInt(signCount);

    if (attestedCredentialData != null) {
      buffer.put(attestedCredentialData);
    }

    if (extensions != null) {
      buffer.put(extensions);
    }

    return buffer.array();
  }

  /**
   * Converts the authenticator data to a Base64 URL-encoded string for JSON serialization.
   *
   * @return the Base64 URL-encoded representation of the authenticator data
   */
  @JsonValue
  public String toJson() {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(encode());
  }

  /**
   * Builder class for constructing AuthenticatorData instances.
   *
   * <p>Provides a fluent API for setting authenticator data properties and automatically handles
   * flag byte construction based on the provided settings.
   */
  public static class Builder {
    private byte[] rpIdHash;
    private boolean userPresent = true;
    private boolean userVerified = false;
    private boolean backupEligible = false;
    private boolean backupState = false;
    private boolean attestedCredentialDataIncluded = false;
    private boolean extensionDataIncluded = false;
    private int signCount = 0;
    private byte[] attestedCredentialData;
    private byte[] extensions;

    /**
     * Sets the RP ID by computing its SHA-256 hash.
     *
     * @param rpId the Relying Party identifier string
     * @return this builder instance
     * @throws RuntimeException if SHA-256 algorithm is not available
     */
    public Builder rpId(String rpId) {
      try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        this.rpIdHash = digest.digest(rpId.getBytes());
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("SHA-256 not available", e);
      }
      return this;
    }

    /**
     * Sets the RP ID hash directly.
     *
     * @param rpIdHash the SHA-256 hash of the Relying Party ID (must be 32 bytes)
     * @return this builder instance
     */
    public Builder rpIdHash(byte[] rpIdHash) {
      this.rpIdHash = rpIdHash;
      return this;
    }

    /**
     * Sets whether the user is present.
     *
     * @param userPresent true if the user is present, false otherwise
     * @return this builder instance
     */
    public Builder userPresent(boolean userPresent) {
      this.userPresent = userPresent;
      return this;
    }

    /**
     * Sets whether the user has been verified.
     *
     * @param userVerified true if the user has been verified, false otherwise
     * @return this builder instance
     */
    public Builder userVerified(boolean userVerified) {
      this.userVerified = userVerified;
      return this;
    }

    /**
     * Sets whether the credential is backup eligible.
     *
     * @param backupEligible true if the credential can be backed up, false otherwise
     * @return this builder instance
     */
    public Builder backupEligible(boolean backupEligible) {
      this.backupEligible = backupEligible;
      return this;
    }

    /**
     * Sets the backup state of the credential.
     *
     * @param backupState true if the credential is currently backed up, false otherwise
     * @return this builder instance
     */
    public Builder backupState(boolean backupState) {
      this.backupState = backupState;
      return this;
    }

    /**
     * Sets the signature counter value.
     *
     * @param signCount the signature counter value
     * @return this builder instance
     */
    public Builder signCount(int signCount) {
      this.signCount = signCount;
      return this;
    }

    /**
     * Sets the attested credential data.
     *
     * @param attestedCredentialData the attested credential data bytes (may be null)
     * @return this builder instance
     */
    public Builder attestedCredentialData(byte[] attestedCredentialData) {
      this.attestedCredentialData = attestedCredentialData;
      this.attestedCredentialDataIncluded = (attestedCredentialData != null);
      return this;
    }

    /**
     * Sets the extension data.
     *
     * @param extensions the extension data bytes (may be null)
     * @return this builder instance
     */
    public Builder extensions(byte[] extensions) {
      this.extensions = extensions;
      this.extensionDataIncluded = (extensions != null);
      return this;
    }

    /**
     * Builds and returns an AuthenticatorData instance.
     *
     * <p>The flags byte is automatically constructed based on the boolean properties set on this
     * builder.
     *
     * @return a new AuthenticatorData instance
     * @throws IllegalArgumentException if rpIdHash is null or not 32 bytes
     */
    public AuthenticatorData build() {
      byte flags = 0;
      if (userPresent) flags |= FLAG_UP;
      if (userVerified) flags |= FLAG_UV;
      if (backupEligible) flags |= FLAG_BE;
      if (backupState) flags |= FLAG_BS;
      if (attestedCredentialDataIncluded) flags |= FLAG_AT;
      if (extensionDataIncluded) flags |= FLAG_ED;

      return new AuthenticatorData(rpIdHash, flags, signCount, attestedCredentialData, extensions);
    }
  }
}
