package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2;

/**
 * Creates the appropriate Security2Crypto provider based on the environment in which this code is running
 *
 * @author Dave Badia
 *
 */
class ZWaveSecurity2CryptoProviderFactory {

    private ZWaveSecurity2CryptoProviderFactory() {
        // Factory class cannot be instantiated
    }

    /**
     * Creates the appropriate Security2Crypto provider based on the environment in which this code is running
     *
     * @return the provider
     * @throws ZWaveSecurity2CryptoException if an unrecoverable error occurs during initialization
     */
    protected static ZWaveSecurity2CryptoProvider createSecurity2CryptoProvider() throws ZWaveSecurity2CryptoException {
        return new ZWaveSecurity2CryptoBouncyCastleProvider();
    }
}
