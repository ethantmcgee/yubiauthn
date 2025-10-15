package dev.ethantmcgee.yubiauthn.model;

public record User(String displayName, String id, String name) {
  public User {
    if (displayName == null) {
      throw new IllegalArgumentException("displayName cannot be null");
    }
    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }
    if (name == null) {
      throw new IllegalArgumentException("name cannot be null");
    }
  }
}
