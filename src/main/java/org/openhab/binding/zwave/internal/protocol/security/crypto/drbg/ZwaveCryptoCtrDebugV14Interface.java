package org.openhab.binding.zwave.internal.protocol.security.crypto.drbg;

public interface ZwaveCryptoCtrDebugV14Interface {

    public void init(byte[] entropy, byte[] personalizationString);

    public void reseed(byte[] providedData);

    public byte[] generate(int len);
}
