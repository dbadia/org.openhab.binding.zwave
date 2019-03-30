package org.openhab.binding.zwave.internal.protocol.security;

/**
 * Creates the appropriate Security2Crypto provider based on the environment in which this code is running
 *
 * @author Dave Badia
 *
 */
class ZWaveCryptoProviderFactory {

    private ZWaveCryptoProviderFactory() {
        // Factory class cannot be instantiated
    }

    /**
     * Creates the appropriate Security2Crypto provider based on the environment in which this code is running
     *
     * @return the provider
     * @throws ZWaveCryptoException if an unrecoverable error occurs during initialization
     */
    protected static ZWaveCryptoProvider createSecurity2CryptoProvider() throws ZWaveCryptoException {
        return new ZWaveCryptoBouncyCastleProvider();
    }
}
