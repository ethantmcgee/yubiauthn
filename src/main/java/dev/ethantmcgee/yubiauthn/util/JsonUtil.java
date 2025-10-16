package dev.ethantmcgee.yubiauthn.util;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

/** Utility class for JSON serialization and deserialization operations. */
public class JsonUtil {
  /**
   * Creates and returns a configured ObjectMapper instance for JSON operations.
   *
   * <p>The returned mapper is configured with:
   *
   * <ul>
   *   <li>Ignores unknown properties during deserialization
   *   <li>Does not fail on empty beans during serialization
   *   <li>Excludes null values from serialization
   *   <li>Supports JDK8 types (Optional, etc.)
   * </ul>
   *
   * @return a configured ObjectMapper instance
   */
  public static ObjectMapper getJsonMapper() {
    return new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
        .setDefaultPropertyInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
        .registerModule(new Jdk8Module());
  }
}
