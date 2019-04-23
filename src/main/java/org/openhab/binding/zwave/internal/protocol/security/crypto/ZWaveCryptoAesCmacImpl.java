package org.openhab.binding.zwave.internal.protocol.security.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
            Mac mac = Mac.getInstance("AESCMAC", new BouncyCastleProvider());
            mac.init(secretKey);
            for (byte[] bytes : dataToMacArray) {
                mac.update(bytes);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new ZWaveCryptoException("Error during AES-CMAC encryption", e);
        }
    }

    public static void main(String[] args) {
        try {
            Mac mac = Mac.getInstance("AESCMAC", new BouncyCastleProvider());
            // Signature signe = Signature.getInstance("ALG_AES_MAC_128_NOPAD");
            // signe.init(key, Signature.MODE_SIGN);
            // signe.sign(buffer, (short) 16, (short) (lc - 16), buffer, (short) 16);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
