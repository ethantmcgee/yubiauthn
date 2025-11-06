package dev.ethantmcgee.yubiauthn.storage;

import static org.assertj.core.api.Assertions.*;

import dev.ethantmcgee.yubiauthn.crypto.CryptoUtils;
import dev.ethantmcgee.yubiauthn.model.COSEAlgorithmIdentifier;
import dev.ethantmcgee.yubiauthn.model.StoredCredential;
import java.security.KeyPair;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CredentialStoreTest {
  private CredentialStore store;

  @BeforeEach
  void setUp() {
    store = new InMemoryCredentialStore();
  }

  @Test
  void testStoreAndRetrieve() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] credentialId = CryptoUtils.generateCredentialId();
    String credId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);

    StoredCredential credential = new StoredCredential(
        credentialId,
        keyPair,
        COSEAlgorithmIdentifier.ES256,
        "example.com",
        "user123",
        1,
        false,
        null
    );

    store.store(credId, credential);
    var retrieved = store.retrieve(credId);

    assertThat(retrieved).isPresent();
    assertThat(retrieved.get()).isEqualTo(credential);
  }

  @Test
  void testRetrieveNonExistent() {
    var retrieved = store.retrieve("nonexistent");
    assertThat(retrieved).isEmpty();
  }

  @Test
  void testFindByRpId() throws Exception {
    KeyPair keyPair1 = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    KeyPair keyPair2 = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);

    byte[] credId1 = CryptoUtils.generateCredentialId();
    byte[] credId2 = CryptoUtils.generateCredentialId();

    StoredCredential cred1 = new StoredCredential(
        credId1, keyPair1, COSEAlgorithmIdentifier.ES256,
        "example.com", "user1", 1, false, null
    );
    StoredCredential cred2 = new StoredCredential(
        credId2, keyPair2, COSEAlgorithmIdentifier.ES256,
        "example.com", "user2", 1, false, null
    );

    store.store(Base64.getUrlEncoder().withoutPadding().encodeToString(credId1), cred1);
    store.store(Base64.getUrlEncoder().withoutPadding().encodeToString(credId2), cred2);

    var found = store.findByRpId("example.com");
    assertThat(found).hasSize(2);
  }

  @Test
  void testFindByRpId_NoMatches() {
    var found = store.findByRpId("nonexistent.com");
    assertThat(found).isEmpty();
  }

  @Test
  void testRemove() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] credentialId = CryptoUtils.generateCredentialId();
    String credId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);

    StoredCredential credential = new StoredCredential(
        credentialId, keyPair, COSEAlgorithmIdentifier.ES256,
        "example.com", "user123", 1, false, null
    );

    store.store(credId, credential);
    assertThat(store.retrieve(credId)).isPresent();

    boolean removed = store.remove(credId);
    assertThat(removed).isTrue();
    assertThat(store.retrieve(credId)).isEmpty();
  }

  @Test
  void testRemove_NonExistent() {
    boolean removed = store.remove("nonexistent");
    assertThat(removed).isFalse();
  }

  @Test
  void testClear() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] credentialId = CryptoUtils.generateCredentialId();
    String credId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);

    StoredCredential credential = new StoredCredential(
        credentialId, keyPair, COSEAlgorithmIdentifier.ES256,
        "example.com", "user123", 1, false, null
    );

    store.store(credId, credential);
    assertThat(store.size()).isEqualTo(1);

    store.clear();
    assertThat(store.size()).isZero();
    assertThat(store.retrieve(credId)).isEmpty();
  }

  @Test
  void testSize() throws Exception {
    assertThat(store.size()).isZero();

    for (int i = 0; i < 5; i++) {
      KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
      byte[] credentialId = CryptoUtils.generateCredentialId();
      String credId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);

      StoredCredential credential = new StoredCredential(
          credentialId, keyPair, COSEAlgorithmIdentifier.ES256,
          "example.com", "user" + i, 1, false, null
      );

      store.store(credId, credential);
    }

    assertThat(store.size()).isEqualTo(5);
  }

  @Test
  void testStore_NullId() throws Exception {
    KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
    byte[] credentialId = CryptoUtils.generateCredentialId();

    StoredCredential credential = new StoredCredential(
        credentialId, keyPair, COSEAlgorithmIdentifier.ES256,
        "example.com", "user123", 1, false, null
    );

    assertThatThrownBy(() -> store.store(null, credential))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Credential ID must not be null");
  }

  @Test
  void testStore_NullCredential() {
    assertThatThrownBy(() -> store.store("id", null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Credential must not be null");
  }

  @Test
  void testConcurrentAccess() throws Exception {
    int numThreads = 10;
    int credentialsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    CountDownLatch latch = new CountDownLatch(numThreads);

    for (int t = 0; t < numThreads; t++) {
      final int threadNum = t;
      executor.submit(() -> {
        try {
          for (int i = 0; i < credentialsPerThread; i++) {
            KeyPair keyPair = CryptoUtils.generateKeyPair(COSEAlgorithmIdentifier.ES256);
            byte[] credentialId = CryptoUtils.generateCredentialId();
            String credId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);

            StoredCredential credential = new StoredCredential(
                credentialId, keyPair, COSEAlgorithmIdentifier.ES256,
                "example.com", "user" + threadNum + "-" + i,
                1, false, null
            );

            store.store(credId, credential);
            store.retrieve(credId);
          }
        } catch (Exception e) {
          throw new RuntimeException(e);
        } finally {
          latch.countDown();
        }
      });
    }

    latch.await(30, TimeUnit.SECONDS);
    executor.shutdown();

    assertThat(store.size()).isEqualTo(numThreads * credentialsPerThread);
  }
}
