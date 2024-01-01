/*
 * Copyright (c) 2010-2025 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
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
public interface ZWaveSecurityCommandClass {
    public byte[] decapsulateSecurityMessage(byte[] ciphertextBytes);

    public byte[] securelyEncapsulateTransaction(byte[] payload);

    public void setNetworkKeys(ZWaveSecurityNetworkKeys securityNetworkKeys);

    public String getAbbreviation();

    public boolean isNonceAvailable();

    public ZWaveMessagePayloadTransaction buildSecurityNonceGet();
}
