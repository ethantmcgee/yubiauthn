package dev.ethantmcgee.yubiauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryCredentialStore implements CredentialRepository {
  private final ConcurrentHashMap<String, ByteArray> usernameToUserHandle =
      new ConcurrentHashMap<>();
  private final ConcurrentHashMap<ByteArray, ConcurrentHashMap<ByteArray, RegisteredCredential>>
      userHandleToCredential = new ConcurrentHashMap<>();

  @Override
  public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
    final var userExists = usernameToUserHandle.containsKey(username);
    if (!userExists) {
      return Set.of();
    }

    final Set<PublicKeyCredentialDescriptor> results = new HashSet<>();
    final var userHandle = usernameToUserHandle.get(username);
    final var credentials = userHandleToCredential.get(userHandle);
    if (credentials == null) {
      return results;
    }

    credentials
        .values()
        .forEach(
            credential ->
                PublicKeyCredentialDescriptor.builder().id(credential.getCredentialId()).build());
    return results;
  }

  @Override
  public Optional<ByteArray> getUserHandleForUsername(String username) {
    return Optional.ofNullable(usernameToUserHandle.get(username));
  }

  @Override
  public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
    for (var entry : usernameToUserHandle.entrySet()) {
      if (entry.getValue().equals(userHandle)) {
        return Optional.of(entry.getKey());
      }
    }
    return Optional.empty();
  }

  @Override
  public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
    final var userExists = usernameToUserHandle.containsValue(userHandle);
    if (!userExists) {
      return Optional.empty();
    }
    return Optional.ofNullable(userHandleToCredential.get(userHandle).get(credentialId));
  }

  @Override
  public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
    final Set<RegisteredCredential> results = new HashSet<>();
    userHandleToCredential
        .values()
        .forEach(
            credentials ->
                credentials
                    .values()
                    .forEach(
                        credential -> {
                          if (credential.getCredentialId().equals(credentialId)) {
                            results.add(credential);
                          }
                        }));
    return results;
  }

  public void addCredential(
      String username, ByteArray userHandle, RegisteredCredential credential) {
    usernameToUserHandle.put(username, userHandle);
    userHandleToCredential
        .computeIfAbsent(userHandle, k -> new ConcurrentHashMap<>())
        .put(credential.getCredentialId(), credential);
  }
}
