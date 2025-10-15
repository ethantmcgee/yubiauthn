package dev.ethantmcgee.yubiauthn.model;

public record RelyingParty(String id, String name) {
  public RelyingParty {
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (name == null) {
      throw new IllegalArgumentException("name cannot be null");
    }
  }
}
