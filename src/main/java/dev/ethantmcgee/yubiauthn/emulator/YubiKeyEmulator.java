package dev.ethantmcgee.yubiauthn.emulator;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredential;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialAssertionOptions;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialCreationOptions;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;
import java.util.HashMap;
import java.util.Map;
import lombok.Builder;

@Builder(toBuilder = true)
public class YubiKeyEmulator {
  @Builder.Default private final ObjectMapper jsonMapper = JsonUtil.getJsonMapper();
  @Builder.Default private final Map<String, PublicKeyCredential> credentials = new HashMap<>();

  public PublicKeyCredential create(String json) throws Exception {
    return create(jsonMapper.readValue(json, PublicKeyCredentialCreationOptions.class));
  }

  public PublicKeyCredential create(PublicKeyCredentialCreationOptions options) throws Exception {
    return null;
  }

  public PublicKeyCredential get(String json) throws Exception {
    return get(jsonMapper.readValue(json, PublicKeyCredentialAssertionOptions.class));
  }

  public PublicKeyCredential get(PublicKeyCredentialAssertionOptions options) throws Exception {
    return null;
  }
}
