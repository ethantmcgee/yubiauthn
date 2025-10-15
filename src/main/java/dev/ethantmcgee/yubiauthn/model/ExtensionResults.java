package dev.ethantmcgee.yubiauthn.model;

public record ExtensionResults(
    CredPropsResult credProps,
    Integer credProtect,
    Integer minPinLength
) {
}
