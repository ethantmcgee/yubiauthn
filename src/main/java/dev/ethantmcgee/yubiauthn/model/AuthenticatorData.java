package dev.ethantmcgee.yubiauthn.model;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Authenticator data structure as defined in WebAuthn specification.
 * Contains information about the authenticator and the credential.
 */
public class AuthenticatorData {
    private static final int FLAG_UP = 0x01;  // User Present
    private static final int FLAG_UV = 0x04;  // User Verified
    private static final int FLAG_BE = 0x08;  // Backup Eligible
    private static final int FLAG_BS = 0x10;  // Backup State
    private static final int FLAG_AT = 0x40;  // Attested Credential Data included
    private static final int FLAG_ED = 0x80;  // Extension Data included

    private final byte[] rpIdHash;
    private final byte flags;
    private final int signCount;
    private final byte[] attestedCredentialData;
    private final byte[] extensions;

    public AuthenticatorData(byte[] rpIdHash, byte flags, int signCount,
                            byte[] attestedCredentialData, byte[] extensions) {
        if (rpIdHash == null || rpIdHash.length != 32) {
            throw new IllegalArgumentException("RP ID hash must be 32 bytes");
        }
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = signCount;
        this.attestedCredentialData = attestedCredentialData;
        this.extensions = extensions;
    }

    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    public byte getFlags() {
        return flags;
    }

    public int getSignCount() {
        return signCount;
    }

    public byte[] getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public byte[] getExtensions() {
        return extensions;
    }

    /**
     * Encodes the authenticator data into bytes as per WebAuthn specification.
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
     * Builder for creating AuthenticatorData with proper flags.
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

        public Builder rpId(String rpId) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                this.rpIdHash = digest.digest(rpId.getBytes());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA-256 not available", e);
            }
            return this;
        }

        public Builder rpIdHash(byte[] rpIdHash) {
            this.rpIdHash = rpIdHash;
            return this;
        }

        public Builder userPresent(boolean userPresent) {
            this.userPresent = userPresent;
            return this;
        }

        public Builder userVerified(boolean userVerified) {
            this.userVerified = userVerified;
            return this;
        }

        public Builder backupEligible(boolean backupEligible) {
            this.backupEligible = backupEligible;
            return this;
        }

        public Builder backupState(boolean backupState) {
            this.backupState = backupState;
            return this;
        }

        public Builder signCount(int signCount) {
            this.signCount = signCount;
            return this;
        }

        public Builder attestedCredentialData(byte[] attestedCredentialData) {
            this.attestedCredentialData = attestedCredentialData;
            this.attestedCredentialDataIncluded = (attestedCredentialData != null);
            return this;
        }

        public Builder extensions(byte[] extensions) {
            this.extensions = extensions;
            this.extensionDataIncluded = (extensions != null);
            return this;
        }

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
