package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.openhab.binding.zwave.internal.protocol.security.crypto.interfaces.ZWaveCryptoAesCmac;

/**
 * Uses default JCE provider that is JRE 8+
 *
 * @author Dave Badia
 *
 */
class ZWaveCryptoAesCmacImpl implements ZWaveCryptoAesCmac {

    /**
     * {@inheritDoc}
     *
     */
    @Override
    public byte[] performAesCmac(SecretKey secretKey, byte[]... dataToMacArray) throws ZWaveCryptoException {
        try {
            Mac mac = Mac.getInstance("AESCMAC");
            mac.init(secretKey);
            for (byte[] bytes : dataToMacArray) {
                mac.update(bytes);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new ZWaveCryptoException("Error during AES-CMAC encryption", e);
        }
    }

}
