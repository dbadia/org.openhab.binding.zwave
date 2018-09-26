package org.openhab.binding.zwave.internal.protocol.commandclass;

/**
 * Interface to allow for generic handling of security encapsulation and decapsulation
 *
 * @see ZWaveSecurity0CommandClass
 * @see ZWaveSecurity2CommandClass
 *
 * @author Dave Badia
 *
 */
public interface ZWaveSecurityCommand {
    public byte[] decapsulateSecurityMessage(byte[] ciphertextBytes);

    public byte[] securelyEncapsulateTransaction(byte[] payload);
}
