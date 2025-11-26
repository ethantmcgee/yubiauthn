package dev.ethantmcgee.yubiauthn.emulator;

public interface SmartCardConnection {
  byte[] sendAndReceive(byte[] bytes);
}
