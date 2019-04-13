/**
 * Copyright (c) 2010-2018 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zwave.internal.protocol.serialmessage;

import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageClass;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveSerialMessageException;
import org.openhab.binding.zwave.internal.protocol.ZWaveSerialPayload;
import org.openhab.binding.zwave.internal.protocol.ZWaveTransaction;
import org.openhab.binding.zwave.internal.protocol.security.crypto.ZWaveCryptoException;
import org.openhab.binding.zwave.internal.protocol.transaction.ZWaveTransactionMessageBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class processes a serial message from the zwave controller
 *
 * @author Dave Badia
 */
public class GetRandomMessageClass extends ZWaveCommandProcessor {
    private final Logger logger = LoggerFactory.getLogger(GetRandomMessageClass.class);

    private String responseError = "controller GET_RANDOM generic error";
    private byte[] randomBytes;

    /**
     * @param requestedBytes range between 2 and 32
     */
    public ZWaveSerialPayload doRequest(byte requestedBytes) {
        logger.debug("Creating GET_RANDOM message");
        if (requestedBytes < 2 || requestedBytes > 32) {
            throw new IllegalArgumentException("requestedBytes must be between 2 and 32");
        }
        // Create the request
        return new ZWaveTransactionMessageBuilder(SerialMessageClass.GetRandom)
                .withPayload(new byte[] { requestedBytes }).build();
    }

    @Override
    public boolean handleResponse(ZWaveController zController, ZWaveTransaction transaction,
            SerialMessage incomingMessage) throws ZWaveSerialMessageException {
        logger.trace("Handle Message Get Random - Length {}", incomingMessage.getMessagePayload().length);

        logger.debug("GET_RANDOM result = {}", SerialMessage.bb2hex(incomingMessage.getMessagePayload()));
        transaction.setTransactionComplete();
        boolean success = incomingMessage.getMessagePayloadByte(0) == 1;
        if (success && incomingMessage.getMessagePayload().length > 1) {
            int responseLength = incomingMessage.getMessagePayloadByte(1);
            randomBytes = new byte[responseLength];
            System.arraycopy(incomingMessage.getMessagePayload(), 2, randomBytes, 0, responseLength);
            responseError = null;
        } else {
            responseError = "controller GET_RANDOM call failed: "
                    + SerialMessage.bb2hex(incomingMessage.getMessagePayload());
        }
        return true;
    }

    public byte[] getRandomBytes() throws ZWaveCryptoException {
        if (responseError != null) {
            throw new ZWaveCryptoException(responseError);
        }
        return randomBytes;
    }

}
