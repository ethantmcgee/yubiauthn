package dev.ethantmcgee.yubiauthn.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;

/**
 * Represents a credential created or used during a WebAuthn ceremony.
 *
 * <p>This record models the PublicKeyCredential interface from the Web Authentication API.
 * It contains information about the credential including its ID, type, and authenticator response.
 *
 * @param <T> The type of response (either {@link RegistrationResponse} or {@link AssertionResponse})
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential">MDN - PublicKeyCredential</a>
 * @see <a href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">W3C WebAuthn - PublicKeyCredential Interface</a>
 */
public record PublicKeyCredential<T>(
    AuthenticatorAttachmentType authenticatorAttachment,
    String id,
    String rawId,
    T response,
    CredentialType type,
    ExtensionResults clientExtensionResults) {
  public PublicKeyCredential {
    if (authenticatorAttachment == null) {
      authenticatorAttachment = AuthenticatorAttachmentType.PLATFORM;
    }
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (rawId == null) {
      throw new IllegalArgumentException("rawId cannot be null");
    }
    if (response == null) {
      throw new IllegalArgumentException("response cannot be null");
    }
    if (type == null) {
      type = CredentialType.PUBLIC_KEY;
    }
  }

  public String toJson() throws JsonProcessingException {
    return JsonUtil.getJsonMapper().writeValueAsString(this);
  }
}
