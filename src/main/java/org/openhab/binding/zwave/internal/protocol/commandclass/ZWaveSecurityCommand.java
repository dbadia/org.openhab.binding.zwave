package org.openhab.binding.zwave.internal.protocol.commandclass;

import org.openhab.binding.zwave.internal.protocol.ZWaveMessagePayloadTransaction;
import org.openhab.binding.zwave.internal.protocol.security.ZWaveSecurityNetworkKeys;

/**
 * Interface to allow for generic handling of security encapsulation and decapsulation
 *
 * @see ZWaveSecurity0CommandClass
 * @see ZWaveSecurity2CommandClass
 *
 * @author Dave Badia
 *
 */
public interface ZWaveSecurityCommand { // TODO: rename to ZWaveSecurityCommandClass
    public byte[] decapsulateSecurityMessage(byte[] ciphertextBytes);

    public byte[] securelyEncapsulateTransaction(byte[] payload);

    public void setNetworkKeys(ZWaveSecurityNetworkKeys securityNetworkKeys);

    public String getAbbreviation();

    public boolean isNonceAvailable();

    public ZWaveMessagePayloadTransaction buildSecurityNonceGet();
}
