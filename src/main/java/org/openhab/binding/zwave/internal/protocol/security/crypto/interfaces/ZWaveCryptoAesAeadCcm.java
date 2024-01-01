package org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces;

import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoException;

public interface ZWaveCryptoAesAeadCcm {

    /**
     * TODO: doc
     *
     * @param secretKey
     * @param dataToMacArray
     * @return
     * @throws ZWaveCryptoException
     */
    public abstract int computeAesCcmOutputSize(int plaintextLength, byte[] nonce, byte[] additionalAuthenticationData);

    /**
     * TODO: doc
     *
     * @param secretKey
     * @param dataToMacArray
     * @return
     * @throws ZWaveCryptoException
     */
    public abstract byte[] performAesCcmCrypt(boolean encrypt, byte[] inputBytes, byte[] keyBytes, byte[] nonce,
            byte[] additionalAuthenticationData) throws ZWaveCryptoException;
}
