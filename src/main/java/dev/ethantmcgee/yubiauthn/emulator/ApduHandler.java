package dev.ethantmcgee.yubiauthn.emulator;

import dev.ethantmcgee.yubiauthn.emulator.scp.Scp11bHandler;
import dev.ethantmcgee.yubiauthn.emulator.scp.Scp11bHandler.Tlv;
import dev.ethantmcgee.yubiauthn.emulator.scp.ScpState;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;

/**
 * Handles APDU command processing for YubiKey emulation.
 *
 * <p>This class implements the APDU protocol for Security Domain, Management, and FIDO applets,
 * including SCP11b secure channel support.
 */
public class ApduHandler {

  // Application IDs
  private static final byte[] AID_SECURITY_DOMAIN = hexToBytes("a000000151000000");
  private static final byte[] AID_MANAGEMENT = hexToBytes("a000000527471117");
  private static final byte[] AID_FIDO = hexToBytes("a0000006472f0001");

  // Status words
  private static final short SW_SUCCESS = (short) 0x9000;
  private static final short SW_BYTES_REMAINING_PREFIX = (short) 0x6100;
  private static final short SW_WRONG_DATA = (short) 0x6A80;
  private static final short SW_FILE_NOT_FOUND = (short) 0x6A82;
  private static final short SW_INCORRECT_P1P2 = (short) 0x6A86;
  private static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;

  // INS bytes
  private static final byte INS_SELECT = (byte) 0xA4;
  private static final byte INS_GET_DATA = (byte) 0xCA;
  private static final byte INS_GET_RESPONSE = (byte) 0xC0;
  private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
  private static final byte INS_MGMT_READ_CONFIG = (byte) 0x1D;
  private static final byte INS_CTAP2_MSG = (byte) 0x10;

  // SCP11 state
  private final Scp11bHandler scp11bHandler;
  private ScpState scpState;

  // Response chaining
  private byte[] pendingResponse;
  private int pendingOffset;

  // Device info
  private final String firmwareVersion;
  private final byte[] serialNumber;

  /**
   * Creates a new APDU handler.
   *
   * @param scp11bHandler handler for SCP11b operations
   * @param firmwareVersion device firmware version string
   * @param serialNumber device serial number (4 bytes)
   */
  public ApduHandler(Scp11bHandler scp11bHandler, String firmwareVersion, byte[] serialNumber) {
    this.scp11bHandler = scp11bHandler;
    this.firmwareVersion = firmwareVersion;
    this.serialNumber = serialNumber;
  }

  /**
   * Processes an APDU command and returns the response.
   *
   * @param apdu the command APDU
   * @return the response APDU including status word
   */
  public byte[] processApdu(byte[] apdu) {
    if (apdu == null || apdu.length < 4) {
      return toResponse(SW_WRONG_DATA);
    }

    byte cla = apdu[0];
    byte ins = apdu[1];
    byte p1 = apdu[2];
    byte p2 = apdu[3];
    byte[] data = extractData(apdu);

    // Debug: print incoming APDU
    System.out.println("APDU: " + bytesToHex(apdu));

    try {
      byte[] response;
      // Check if this is a secure channel wrapped command
      if (scpState != null && (cla & 0x04) == 0x04) {
        response = processSecureCommand(cla, ins, p1, p2, data);
      } else {
        response =
            switch (ins) {
              case INS_SELECT -> processSelect(p1, p2, data);
              case INS_GET_DATA -> processGetData(p1, p2, data);
              case INS_GET_RESPONSE -> processGetResponse();
              case INS_INTERNAL_AUTHENTICATE -> processInternalAuthenticate(p2, data);
              default -> toResponse(SW_INS_NOT_SUPPORTED);
            };
      }

      // Debug: print response
      System.out.println("RESP: " + bytesToHex(response));
      return response;
    } catch (Exception e) {
      return toResponse(SW_WRONG_DATA);
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  private byte[] extractData(byte[] apdu) {
    if (apdu.length <= 5) {
      return new byte[0];
    }
    int lc = apdu[4] & 0xFF;
    if (lc == 0 && apdu.length > 7) {
      // Extended length
      lc = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
      return Arrays.copyOfRange(apdu, 7, 7 + lc);
    }
    return Arrays.copyOfRange(apdu, 5, 5 + lc);
  }

  private byte[] processSelect(byte p1, byte p2, byte[] data) throws Exception {
    if (p1 != 0x04 || p2 != 0x00) {
      return toResponse(SW_INCORRECT_P1P2);
    }

    scpState = null; // Reset SCP state on applet selection

    if (startsWith(data, AID_SECURITY_DOMAIN)) {
      return processSelectSecurityDomain();
    } else if (startsWith(data, AID_MANAGEMENT)) {
      return processSelectManagement();
    } else if (startsWith(data, AID_FIDO)) {
      return processSelectFido();
    }

    return toResponse(SW_FILE_NOT_FOUND);
  }

  private byte[] processSelectSecurityDomain() throws IOException {
    // Response format: FCI template
    // 6F (FCI Template)
    //   84 (DF Name/AID)
    //   A5 (Proprietary data)
    //     73 (Security Domain Management Data)
    //       06 (OID) 2A 86 48 86 FC 6B 01 - Global Platform OID
    byte[] oid = hexToBytes("2a864886fc6b01");

    // Build from inside out
    byte[] oidTlv = Tlv.encode(0x06, oid);
    byte[] sdmTlv = Tlv.encode(0x73, oidTlv);
    byte[] propTlv = Tlv.encode(0xA5, sdmTlv);
    byte[] aidTlv = Tlv.encode(0x84, AID_SECURITY_DOMAIN);

    ByteArrayOutputStream fciContent = new ByteArrayOutputStream();
    fciContent.write(aidTlv);
    fciContent.write(propTlv);

    byte[] fciTlv = Tlv.encode(0x6F, fciContent.toByteArray());

    return toResponse(fciTlv, SW_SUCCESS);
  }

  private byte[] processSelectManagement() {
    // Response: "Virtual mgr - FW version X.Y.Z" + 9000
    String response = "Virtual mgr - FW version " + firmwareVersion;
    return toResponse(response.getBytes(), SW_SUCCESS);
  }

  private byte[] processSelectFido() {
    // Response: "U2F_V2" + 9000
    return toResponse("U2F_V2".getBytes(), SW_SUCCESS);
  }

  private byte[] processGetData(byte p1, byte p2, byte[] data) throws Exception {
    int tag = ((p1 & 0xFF) << 8) | (p2 & 0xFF);

    // Certificate bundle request (BF21)
    if (tag == 0xBF21) {
      return processGetCertificateBundle(data);
    }

    return toResponse(SW_FILE_NOT_FOUND);
  }

  private byte[] processGetCertificateBundle(byte[] data) throws Exception {
    // Parse request to get key reference
    // Format: A6 (tag) -> 83 (key ref) -> KVN || KID
    List<Tlv> tlvs = Tlv.parseAll(data);
    byte kid = 0;

    for (Tlv tlv : tlvs) {
      if (tlv.tag == 0xA6) {
        List<Tlv> nested = Tlv.parseAll(tlv.value);
        for (Tlv n : nested) {
          if (n.tag == 0x83 && n.value.length >= 2) {
            kid = n.value[1];
          }
        }
      }
    }

    // Return certificates for key ref 0x13 (SCP11b)
    if (kid == 0x13 || kid == 0x01) {
      return buildCertificateResponse();
    }

    return toResponse(SW_FILE_NOT_FOUND);
  }

  private byte[] buildCertificateResponse() throws CertificateEncodingException, IOException {
    List<X509Certificate> certs = scp11bHandler.certificates();
    ByteArrayOutputStream certData = new ByteArrayOutputStream();

    for (X509Certificate cert : certs) {
      byte[] encoded = cert.getEncoded();
      // Each certificate is wrapped in a TLV with tag 0x30 (SEQUENCE)
      // The certificate is already DER encoded with 0x30, so just add it
      certData.write(encoded);
    }

    byte[] fullResponse = certData.toByteArray();

    // If response is too long, use response chaining
    if (fullResponse.length > 255) {
      pendingResponse = fullResponse;
      pendingOffset = 0;
      return sendChunkedResponse();
    }

    return toResponse(fullResponse, SW_SUCCESS);
  }

  private byte[] sendChunkedResponse() {
    int remaining = pendingResponse.length - pendingOffset;
    int chunkSize = Math.min(remaining, 255);

    byte[] chunk = Arrays.copyOfRange(pendingResponse, pendingOffset, pendingOffset + chunkSize);
    pendingOffset += chunkSize;

    remaining = pendingResponse.length - pendingOffset;
    if (remaining > 0) {
      // More data available
      int nextChunk = Math.min(remaining, 255);
      return toResponse(chunk, (short) (SW_BYTES_REMAINING_PREFIX | nextChunk));
    } else {
      // Last chunk
      pendingResponse = null;
      pendingOffset = 0;
      return toResponse(chunk, SW_SUCCESS);
    }
  }

  private byte[] processGetResponse() {
    if (pendingResponse == null) {
      return toResponse(SW_WRONG_DATA);
    }
    return sendChunkedResponse();
  }

  private byte[] processInternalAuthenticate(byte p2, byte[] data) throws Exception {
    // p1 = KVN, p2 = KID (0x13 for SCP11b)
    if (p2 != 0x13) {
      return toResponse(SW_INCORRECT_P1P2);
    }

    Scp11bHandler.Scp11bResult result = scp11bHandler.processInternalAuthenticate(data);
    scpState = result.scpState();

    return toResponse(result.responseData(), SW_SUCCESS);
  }

  private byte[] processSecureCommand(byte cla, byte ins, byte p1, byte p2, byte[] data)
      throws Exception {
    // Secure channel command processing
    // Last 8 bytes of data are the C-MAC

    if (data.length < 8) {
      System.out.println("Data too short for MAC");
      return toResponse(SW_WRONG_DATA);
    }

    // C-MAC is the last 8 bytes
    byte[] cMac = Arrays.copyOfRange(data, data.length - 8, data.length);
    byte[] commandData = Arrays.copyOfRange(data, 0, data.length - 8);

    System.out.println("C-MAC: " + bytesToHex(cMac));
    System.out.println("Command data (without MAC): " + bytesToHex(commandData));

    // Build MAC input: CLA || INS || P1 || P2 || Lc || data (without MAC)
    // The Lc in the MAC calculation should be the length including the MAC
    byte[] macInput;
    int lc = data.length; // Original Lc includes the MAC
    if (commandData.length > 0) {
      macInput =
          ByteBuffer.allocate(5 + commandData.length)
              .put((byte) (cla & 0xFF))
              .put(ins)
              .put(p1)
              .put(p2)
              .put((byte) lc)
              .put(commandData)
              .array();
    } else {
      macInput = new byte[] {(byte) (cla & 0xFF), ins, p1, p2, (byte) lc};
    }

    System.out.println("MAC input: " + bytesToHex(macInput));
    byte[] expectedMac = scpState.mac(macInput);
    System.out.println("Expected MAC: " + bytesToHex(expectedMac));

    if (!MessageDigest.isEqual(cMac, expectedMac)) {
      System.out.println("MAC verification failed!");
      return toResponse(SW_WRONG_DATA);
    }
    System.out.println("MAC verified successfully");

    // Decrypt command data if present
    byte[] decryptedData = commandData;
    if (commandData.length > 0) {
      decryptedData = scpState.decrypt(commandData);
      System.out.println("Decrypted command data: " + bytesToHex(decryptedData));
    }

    // Process the decrypted command
    byte[] plainResponse = processPlainCommand(ins, p1, p2, decryptedData);

    // Extract status word and data from response
    if (plainResponse.length < 2) {
      return toResponse(SW_WRONG_DATA);
    }

    short sw =
        (short)
            (((plainResponse[plainResponse.length - 2] & 0xFF) << 8)
                | (plainResponse[plainResponse.length - 1] & 0xFF));
    byte[] responseData = Arrays.copyOf(plainResponse, plainResponse.length - 2);

    System.out.println("Plain response data: " + bytesToHex(responseData));
    System.out.println("Plain response SW: " + String.format("%04x", sw & 0xFFFF));

    // Encrypt response data if present
    byte[] encryptedResponse = responseData;
    if (responseData.length > 0) {
      encryptedResponse = scpState.encrypt(responseData);
      System.out.println("Encrypted response data: " + bytesToHex(encryptedResponse));
    }

    // Compute response MAC over encrypted data
    byte[] responseMac = scpState.computeResponseMac(encryptedResponse, sw);
    System.out.println("Response MAC: " + bytesToHex(responseMac));

    // Build secure response: encrypted_data || R-MAC || SW
    ByteArrayOutputStream secureResponse = new ByteArrayOutputStream();
    secureResponse.write(encryptedResponse);
    secureResponse.write(responseMac);
    secureResponse.write((sw >> 8) & 0xFF);
    secureResponse.write(sw & 0xFF);

    return secureResponse.toByteArray();
  }

  private byte[] processPlainCommand(byte ins, byte p1, byte p2, byte[] data) throws Exception {
    return switch (ins) {
      case INS_GET_DATA -> processGetData(p1, p2, data);
      case INS_MGMT_READ_CONFIG -> processManagementReadConfig();
      case INS_CTAP2_MSG -> processCtap2Message(data);
      default -> toResponse(SW_INS_NOT_SUPPORTED);
    };
  }

  private byte[] processCtap2Message(byte[] data) throws IOException {
    // CTAP2 command processing
    // p1: 0x80 = last fragment or only fragment, 0x00 = more fragments
    // p2: 0x00

    if (data.length < 1) {
      // Return CTAP2 error: CTAP2_ERR_INVALID_LENGTH
      return toResponse(new byte[] {0x03}, SW_SUCCESS);
    }

    byte ctapCommand = data[0];
    byte[] ctapData = data.length > 1 ? Arrays.copyOfRange(data, 1, data.length) : new byte[0];

    byte[] ctapResponse =
        switch (ctapCommand) {
          case 0x04 -> processCtap2GetInfo();
          case 0x06 -> processCtap2ClientPin(ctapData);
          case 0x0d -> processCtap2Config(ctapData);
          default -> new byte[] {0x01}; // CTAP1_ERR_INVALID_COMMAND
        };

    return toResponse(ctapResponse, SW_SUCCESS);
  }

  private byte[] processCtap2GetInfo() throws IOException {
    // Return CBOR-encoded authenticatorGetInfo response
    // CTAP2_OK (0x00) followed by CBOR map
    ByteArrayOutputStream response = new ByteArrayOutputStream();
    response.write(0x00); // CTAP2_OK

    // Build CBOR response - map with multiple entries
    // Using simple hardcoded CBOR for required fields
    ByteArrayOutputStream cbor = new ByteArrayOutputStream();

    // Start a CBOR map with ~8 entries (A8 = map with 8 items)
    cbor.write(0xA8);

    // 0x01: versions - array of strings
    cbor.write(0x01); // key
    cbor.write(0x83); // array(3)
    cbor.write(0x66); // text(6) - "U2F_V2"
    cbor.write("U2F_V2".getBytes());
    cbor.write(0x68); // text(8) - "FIDO_2_0"
    cbor.write("FIDO_2_0".getBytes());
    cbor.write(0x6C); // text(12) - "FIDO_2_1_PRE"
    cbor.write("FIDO_2_1_PRE".getBytes());

    // 0x02: extensions - array of strings
    cbor.write(0x02); // key
    cbor.write(0x82); // array(2)
    cbor.write(0x6B); // text(11) - "credProtect"
    cbor.write("credProtect".getBytes());
    cbor.write(0x6B); // text(11) - "hmac-secret"
    cbor.write("hmac-secret".getBytes());

    // 0x03: aaguid - 16 bytes
    cbor.write(0x03); // key
    cbor.write(0x50); // bytes(16)
    // YubiKey 5 series AAGUID (fa2b99dc-9e39-4257-8f92-4a30d23c4118)
    cbor.write(hexToBytes("fa2b99dc9e3942578f924a30d23c4118"));

    // 0x04: options - map
    cbor.write(0x04); // key
    cbor.write(0xA7); // map(7)
    cbor.write(0x62); // text(2) - "rk"
    cbor.write("rk".getBytes());
    cbor.write(0xF5); // true
    cbor.write(0x62); // text(2) - "up"
    cbor.write("up".getBytes());
    cbor.write(0xF5); // true
    cbor.write(0x62); // text(2) - "uv"
    cbor.write("uv".getBytes());
    cbor.write(0xF5); // true
    cbor.write(0x64); // text(4) - "plat"
    cbor.write("plat".getBytes());
    cbor.write(0xF4); // false
    cbor.write(0x69); // text(9) - "clientPin"
    cbor.write("clientPin".getBytes());
    cbor.write(0xF4); // false (no PIN set)
    cbor.write(0x69); // text(9) - "authnrCfg"
    cbor.write("authnrCfg".getBytes());
    cbor.write(0xF5); // true - enables Config commands
    cbor.write(0x6F); // text(15) - "setMinPINLength"
    cbor.write("setMinPINLength".getBytes());
    cbor.write(0xF5); // true

    // 0x05: maxMsgSize - unsigned int
    cbor.write(0x05); // key
    cbor.write(0x19); // uint16
    cbor.write(0x04);
    cbor.write(0x80); // 1152

    // 0x06: pinUvAuthProtocols - array
    cbor.write(0x06); // key
    cbor.write(0x82); // array(2)
    cbor.write(0x02); // 2 (pinUvAuthProtocol 2)
    cbor.write(0x01); // 1 (pinUvAuthProtocol 1)

    // 0x07: maxCredentialCountInList - unsigned int
    cbor.write(0x07); // key
    cbor.write(0x08); // 8

    // 0x08: maxCredentialIdLength - unsigned int
    cbor.write(0x08); // key
    cbor.write(0x18);
    cbor.write(0x80); // 128

    response.write(cbor.toByteArray());
    return response.toByteArray();
  }

  private byte[] processCtap2ClientPin(byte[] data) throws IOException {
    // authenticatorClientPIN command
    // Parse CBOR to get subCommand (key 0x02 in the map)
    // Format: Ax (map) followed by key-value pairs
    // We need to properly skip values to find key 0x02

    int subCommand = 0;
    if (data.length >= 3 && (data[0] & 0xF0) == 0xA0) {
      int numItems = data[0] & 0x0F;
      int pos = 1;

      for (int item = 0; item < numItems && pos < data.length - 1; item++) {
        int key = data[pos++] & 0xFF;
        if (key == 0x02) {
          // Found subCommand key, next byte is the value
          subCommand = data[pos] & 0xFF;
          break;
        }
        // Skip the value based on its type
        pos = skipCborValue(data, pos);
      }
    }

    System.out.println("clientPIN subCommand: " + subCommand);
    ByteArrayOutputStream response = new ByteArrayOutputStream();

    switch (subCommand) {
      case 0x02 -> {
        // getKeyAgreement - return platform key agreement public key
        response.write(0x00); // CTAP2_OK

        // Return CBOR map with key 0x01 (keyAgreement) containing COSE_Key
        ByteArrayOutputStream cbor = new ByteArrayOutputStream();
        cbor.write(0xA1); // map(1)
        cbor.write(0x01); // key: keyAgreement

        // Generate ephemeral key for PIN protocol key agreement
        try {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
          kpg.initialize(new ECGenParameterSpec("secp256r1"));
          KeyPair kp = kpg.generateKeyPair();
          ECPublicKey pubKey = (ECPublicKey) kp.getPublic();

          byte[] x = pubKey.getW().getAffineX().toByteArray();
          byte[] y = pubKey.getW().getAffineY().toByteArray();
          // Remove leading zero and pad to 32 bytes
          x = padTo32Bytes(removeLeadingZero(x));
          y = padTo32Bytes(removeLeadingZero(y));

          // COSE_Key for EC2 (kty=2, crv=1 for P-256)
          cbor.write(0xA5); // map(5)
          cbor.write(0x01); // kty
          cbor.write(0x02); // EC2
          cbor.write(0x03); // alg
          cbor.write(0x26); // -7 (ES256) as negative: 0x26 = -7
          cbor.write(0x20); // crv (-1)
          cbor.write(0x01); // P-256
          cbor.write(0x21); // x (-2)
          cbor.write(0x58);
          cbor.write(0x20); // bytes(32)
          cbor.write(x);
          cbor.write(0x22); // y (-3)
          cbor.write(0x58);
          cbor.write(0x20); // bytes(32)
          cbor.write(y);

          response.write(cbor.toByteArray());
        } catch (Exception e) {
          response.reset();
          response.write(0x11); // CTAP2_ERR_INVALID_PARAMETER
        }
      }
      case 0x03 -> {
        // setPIN - accept the PIN
        // In a real implementation, we would decrypt and store the PIN
        // For emulation, just return success
        response.write(0x00); // CTAP2_OK
      }
      case 0x05 -> {
        // getPinToken - return an encrypted PIN token
        // The response is a map with key 0x02 (pinUvAuthToken)
        response.write(0x00); // CTAP2_OK

        ByteArrayOutputStream cbor = new ByteArrayOutputStream();
        cbor.write(0xA1); // map(1)
        cbor.write(0x02); // key: pinUvAuthToken

        // Return a 32-byte encrypted token (would normally be encrypted with shared secret)
        // For emulation, we return a placeholder token
        cbor.write(0x58);
        cbor.write(0x20); // bytes(32)
        cbor.write(new byte[32]); // Zero-filled token

        response.write(cbor.toByteArray());
      }
      default -> {
        // Other subcommands not implemented
        response.write(0x01); // CTAP1_ERR_INVALID_COMMAND
      }
    }

    return response.toByteArray();
  }

  private byte[] processCtap2Config(byte[] data) {
    // authenticatorConfig command
    // For emulation, we accept all config commands and return success
    // The library uses this for setMinPinLength and other configuration
    System.out.println("Config command received: " + bytesToHex(data));
    return new byte[] {0x00}; // CTAP2_OK - no response data needed
  }

  /** Skip a CBOR value starting at position pos and return the position after it. */
  private int skipCborValue(byte[] data, int pos) {
    if (pos >= data.length) return pos;

    int majorType = (data[pos] & 0xFF) >> 5;
    int additionalInfo = data[pos] & 0x1F;
    pos++;

    int length = 0;
    if (additionalInfo < 24) {
      length = additionalInfo;
    } else if (additionalInfo == 24 && pos < data.length) {
      length = data[pos++] & 0xFF;
    } else if (additionalInfo == 25 && pos + 1 < data.length) {
      length = ((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF);
    }

    switch (majorType) {
      case 0, 1 -> { // Unsigned/negative integer - no additional bytes for small values
        return pos;
      }
      case 2, 3 -> { // Byte string, text string
        return pos + length;
      }
      case 4 -> { // Array
        for (int i = 0; i < length && pos < data.length; i++) {
          pos = skipCborValue(data, pos);
        }
        return pos;
      }
      case 5 -> { // Map
        for (int i = 0; i < length && pos < data.length; i++) {
          pos = skipCborValue(data, pos); // key
          pos = skipCborValue(data, pos); // value
        }
        return pos;
      }
      case 7 -> { // Simple/float
        return pos;
      }
      default -> {
        return pos;
      }
    }
  }

  private byte[] removeLeadingZero(byte[] bytes) {
    if (bytes.length > 0 && bytes[0] == 0) {
      return Arrays.copyOfRange(bytes, 1, bytes.length);
    }
    return bytes;
  }

  private byte[] padTo32Bytes(byte[] bytes) {
    if (bytes.length >= 32) {
      return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
    }
    byte[] padded = new byte[32];
    System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
    return padded;
  }

  private byte[] processManagementReadConfig() throws IOException {
    // Management applet read config command
    // Returns device information TLV encoded
    // The response is length-prefixed: first byte is total length of TLV data

    // Build device info TLVs
    ByteArrayOutputStream tlvData = new ByteArrayOutputStream();

    // Tag 0x02: USB supported capabilities (2 bytes)
    tlvData.write(Tlv.encode(0x02, new byte[] {0x03, 0x07})); // FIDO2, OATH, etc.

    // Tag 0x03: Serial number (4 bytes, big-endian)
    tlvData.write(Tlv.encode(0x03, serialNumber));

    // Tag 0x04: Form factor (1 byte)
    tlvData.write(Tlv.encode(0x04, new byte[] {0x03})); // USB-C with NFC

    // Tag 0x05: Firmware version (3 bytes: major, minor, patch)
    String[] versionParts = firmwareVersion.split("\\.");
    byte[] versionBytes =
        new byte[] {
          Byte.parseByte(versionParts[0]),
          Byte.parseByte(versionParts[1]),
          Byte.parseByte(versionParts[2])
        };
    tlvData.write(Tlv.encode(0x05, versionBytes));

    // Tag 0x06: Auto-eject timeout (2 bytes)
    tlvData.write(Tlv.encode(0x06, new byte[] {0x00, 0x00}));

    // Tag 0x07: Challenge response timeout (1 byte)
    tlvData.write(Tlv.encode(0x07, new byte[] {0x0F}));

    // Tag 0x08: Device flags (1 byte)
    tlvData.write(Tlv.encode(0x08, new byte[] {0x00}));

    // Tag 0x0D: NFC supported capabilities (2 bytes)
    tlvData.write(Tlv.encode(0x0D, new byte[] {0x03, 0x07}));

    // Tag 0x0E: NFC enabled capabilities (2 bytes)
    tlvData.write(Tlv.encode(0x0E, new byte[] {0x03, 0x07}));

    // Tag 0x10: Config lock status (1 byte)
    tlvData.write(Tlv.encode(0x10, new byte[] {0x00}));

    // Tag 0x13: NFC restricted (1 byte)
    tlvData.write(Tlv.encode(0x13, new byte[] {0x00}));

    // Prepend length byte
    byte[] tlvBytes = tlvData.toByteArray();
    ByteArrayOutputStream response = new ByteArrayOutputStream();
    response.write(tlvBytes.length);
    response.write(tlvBytes);

    return toResponse(response.toByteArray(), SW_SUCCESS);
  }

  private byte[] toResponse(short sw) {
    return new byte[] {(byte) ((sw >> 8) & 0xFF), (byte) (sw & 0xFF)};
  }

  private byte[] toResponse(byte[] data, short sw) {
    byte[] response = new byte[data.length + 2];
    System.arraycopy(data, 0, response, 0, data.length);
    response[data.length] = (byte) ((sw >> 8) & 0xFF);
    response[data.length + 1] = (byte) (sw & 0xFF);
    return response;
  }

  private boolean startsWith(byte[] data, byte[] prefix) {
    if (data.length < prefix.length) {
      return false;
    }
    for (int i = 0; i < prefix.length; i++) {
      if (data[i] != prefix[i]) {
        return false;
      }
    }
    return true;
  }

  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte)
              ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
}
