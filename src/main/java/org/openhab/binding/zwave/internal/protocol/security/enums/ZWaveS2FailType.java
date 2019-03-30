package org.openhab.binding.zwave.internal.protocol.security.enums;

/**
 * 3.1.7.4 Security 2 KEX Fail Command - Table 16
 *
 * @author Dave Badia
 *
 */
public enum ZWaveS2FailType {
    /**
     * Key failure indicating that no match exists between requested/granted keys in the network.
     */
    KEX_FAIL_KEX_KEY(0x01),
    /**
     * Scheme failure indicating that no scheme is supported by controller or joining node specified an invalid scheme.
     */
    KEX_FAIL_KEX_SCHEME(0x02),
    /**
     * Curve failure indicating that no curve is supported by controller or joining node specified an invalid curve.
     */
    KEX_FAIL_KEX_CURVES(0x03),
    // Not sure what happened to 0x04, it's missing in the spec doc
    /**
     * Node failed to decrypt received frame.
     */
    KEX_FAIL_DECRYPT(0x05),
    /**
     * User has cancelled the S2 bootstrapping.
     */
    KEX_FAIL_CANCEL(0x06),
    /**
     * The Echo KEX Set/Report frame did not match the earlier exchanged frame.
     */
    KEX_FAIL_AUTH(0x07),
    /**
     * The joining node has requested a key, which was not granted by the including node at an earlier stage.
     */
    KEX_FAIL_KEY_GET(0x08),
    /**
     * Including node failed to decrypt and hence verify the received frame encrypted with exchanged key.
     */
    KEX_FAIL_KEY_VERIFY(0x09),
    /**
     * The including node has transmitted a frame containing a different key than what is currently being exchanged.
     */
    KEX_FAIL_KEY_REPORT(0x0A),
    /**
     * The DSK input by the user is incorrect or the DSK user visual validation indicated a mismatch
     */
    KEX_FAIL_DSK(0x0B),;

    private final int theByte;

    private ZWaveS2FailType(int theByte) {
        this.theByte = theByte;
    }

    public int toByte() {
        return theByte;
    }
}
