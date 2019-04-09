package org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces;

import javax.crypto.SecretKey;

import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoException;

public interface ZWaveCryptoAesCmac {
    /**
     * TODO: doc
     *
     * @param secretKey
     * @param dataToMacArray
     * @return
     * @throws ZWaveCryptoException
     */
    public byte[] performAesCmac(SecretKey secretKey, byte[]... dataToMacArray) throws ZWaveCryptoException;
}
