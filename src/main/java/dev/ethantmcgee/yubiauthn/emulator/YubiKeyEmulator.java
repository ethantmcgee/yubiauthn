package dev.ethantmcgee.yubiauthn.emulator;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ethantmcgee.yubiauthn.model.AssertionResponse;
import dev.ethantmcgee.yubiauthn.model.AttestationFormat;
import dev.ethantmcgee.yubiauthn.model.AuthenticatorAttachmentType;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredential;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialAssertionOptions;
import dev.ethantmcgee.yubiauthn.model.PublicKeyCredentialCreationOptions;
import dev.ethantmcgee.yubiauthn.model.RegistrationResponse;
import dev.ethantmcgee.yubiauthn.model.StoredCredential;
import dev.ethantmcgee.yubiauthn.model.TransportType;
import dev.ethantmcgee.yubiauthn.util.JsonUtil;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Builder;


@Builder(toBuilder = true, buildMethodName = "buildInternal")
public class YubiKeyEmulator {
  private final ObjectMapper jsonMapper = JsonUtil.getJsonMapper();
  private final Map<String, StoredCredential> credentials = new HashMap<>();

  @Builder.Default private String aaguid = null;
  @Builder.Default private String description = null;
  @Builder.Default private KeyPair attestationKeyPair = null;
  @Builder.Default private X509Certificate attestationCertificate = null;
  @Builder.Default private String attestationSubject = null;
  @Builder.Default private int signatureCounter = 0;

  @Builder.Default private List<TransportType> transports = List.of();
  @Builder.Default private List<COSEAlgorithmIdentifier> supportedAlgorithms = List.of();

  @Builder.Default
  private List<AuthenticatorAttachmentType> supportedAttachmentTypes =
      List.of(AuthenticatorAttachmentType.CROSS_PLATFORM, AuthenticatorAttachmentType.PLATFORM);

  @Builder.Default private boolean supportsUserPresence = false;
  @Builder.Default private boolean supportsUserVerification = false;
  @Builder.Default private boolean supportsResidentKey = false;
  @Builder.Default private boolean supportsEnterpriseAttestation = false;

  @Builder.Default private boolean supportsCredProtect = false;
  @Builder.Default private boolean supportsMinPinLength = false;
  @Builder.Default private Integer pinLength = null;

  @Builder.Default private boolean backupEligible = false;
  @Builder.Default private boolean backupState = false;

  @Builder.Default private AttestationFormat attestationFormat = AttestationFormat.PACKED;

  public static class YubiKeyEmulatorBuilder {
    public YubiKeyEmulator build() {
      YubiKeyEmulator res = buildInternal();
      res.init();
      return res;
    }
  }

  private void init() {

  }

  public PublicKeyCredential<RegistrationResponse> create(String json) {
    return create(jsonMapper.readValue(json, PublicKeyCredentialCreationOptions.class));
  }

  public PublicKeyCredential<RegistrationResponse> create(PublicKeyCredentialCreationOptions options) {
    return null;
  }

  public PublicKeyCredential<AssertionResponse> get(String json) {
    return get(jsonMapper.readValue(json, PublicKeyCredentialAssertionOptions.class));
  }

  public PublicKeyCredential<AssertionResponse> get(PublicKeyCredentialAssertionOptions options) {
      return null;
  }
}
