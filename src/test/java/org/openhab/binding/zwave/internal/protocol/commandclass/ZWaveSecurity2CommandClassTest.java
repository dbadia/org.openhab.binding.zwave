/**
 * Copyright (c) 2010-2023 Contributors to the openHAB project
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

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveEndpoint;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.commandclass.ZWaveCommandClass.CommandClass;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.CommandClassSecurityV1;
import org.openhab.binding.zwave.internal.protocol.initialization.InitializationTestHelper;
import org.openhab.binding.zwave.internal.protocol.initialization.ZWaveNodeInitStageAdvancer;
import org.openhab.binding.zwave.internal.protocol.security.crypto.CryptoInitTestHelper;
import org.openhab.binding.zwave.internal.protocol.transaction.ZWaveCommandClassTransactionPayload;

public class ZWaveSecurity2CommandClassTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test
    public void testComputePrk() throws Exception {
        String expected = "6713a485315e7960f918714a4ec0541c";
        byte[] ecdhSharedSecret = HEX.parseHex("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] ourPublicKey = HEX.parseHex("1111111111111111111111111111111111111111111111111111111111111111");
        byte[] devicePublicKey = HEX.parseHex("2222222222222222222222222222222222222222222222222222222222222222");
        byte[] actual = buildZWaveSecurity2CommandClass().computePrk(ecdhSharedSecret, ourPublicKey, devicePublicKey);
        assertEquals(16, actual.length);
        assertEquals(expected, HEX.formatHex(actual));
    }

    @Test
    public void testComputeTemporaryEncryptionKeys() throws Exception {
        ZWaveSecurity2CommandClass s2 = buildZWaveSecurity2CommandClass();
        byte[] prk = HEX.parseHex("6713a485315e7960f918714a4ec0541c");
        s2.deriveTempKeysFromPrk(prk);
        assertNotNull(s2.tempAesCcmKey);
        assertEquals("1b040fb9c43fe8cd3f8307e2364e9d05", HEX.formatHex(s2.tempAesCcmKey.getEncoded()));
        assertEquals("b269a7bb020a8fc2cc28ac4c8b8fb6f531a332eb2a494d1fc4ba5cb591ac8b9c",
                HEX.formatHex(s2.tempPersonalizationString));
    }

    @Test
    public void testDeriveNetworkKeys() throws Exception {
        // TODO:
        // const ret = deriveNetworkKeys(prk);
        // t.deepEqual(ret.keyCCM, Buffer.from("ad38204ab4d5d0a8b2c3c78ec4faf331", "hex"));
        // t.deepEqual(ret.keyMPAN, Buffer.from("017070bc421f47fe8c0315bfab605d70", "hex"));
        // t.deepEqual(ret.personalizationString,
        // Buffer.from("8bece5005a4cdcfa855d597b2590eeb38b35b2e7a90d55ca8c8a2507d4a182ff", "hex"));
        // t.deepEqual("done", "done");
    }

    @Disabled // "java.lang.SecurityException: Invalid signature file digest for Manifest main attributes" whenever
              // bouncy castle classes are invoked :(
    @Test
    public void testSecureInclusion() throws Exception {
        CryptoInitTestHelper.initCryptoForTesting(null, null);
        // Mocks
        byte nodeId = 0x01;
        byte[] payload = { nodeId, 2, (byte) CommandClass.COMMAND_CLASS_SECURITY.getKey(),
                CommandClassSecurityV1.SECURITY_COMMANDS_SUPPORTED_GET, };
        ZWaveNode nodeTx = Mockito.mock(ZWaveNode.class);
        Mockito.when(nodeTx.getNodeId()).thenReturn(0x02);
        ZWaveController controllerTx = Mockito.mock(ZWaveController.class);
        Mockito.when(controllerTx.getOwnNodeId()).thenReturn(0x01);

        ZWaveNode nodeRx = Mockito.mock(ZWaveNode.class);
        Mockito.when(nodeRx.getNodeId()).thenReturn(0x01);
        ZWaveController controllerRx = Mockito.mock(ZWaveController.class);
        Mockito.when(controllerRx.getOwnNodeId()).thenReturn(0x02);
        ArgumentCaptor<ZWaveCommandClassTransactionPayload> argumentRx = ArgumentCaptor
                .forClass(ZWaveCommandClassTransactionPayload.class);
        Mockito.doNothing().when(controllerRx).enqueue(argumentRx.capture());
        Mockito.when(controllerRx.getSecurityKeys()).thenReturn(CryptoInitTestHelper.keys);

        ZWaveEndpoint endpoint = Mockito.mock(ZWaveEndpoint.class);
        ZWaveSecurity2CommandClass security2CC = new ZWaveSecurity2CommandClass(nodeRx, controllerRx, endpoint);

        // Start our test

        ZWaveNodeInitStageAdvancer initStageAdvancer = new ZWaveNodeInitStageAdvancer(nodeRx, controllerRx);
        InitializationTestHelper.invokeDoSecureS2Stages(initStageAdvancer, security2CC);
        // keys.addKey(ZWaveKeyType.S0, TEST_KEY);
        // securityRx.setNetworkKey(TEST_KEY);
        //
        // // Create the transmit node
        // ZWaveSecurityCommandClass securityTx = new ZWaveSecurity0CommandClass(nodeTx, controllerTx, endpoint);
        // securityTx.setNetworkKey(TEST_KEY);
        //
        // // Create the nonce request in the transmit node, and send it to the receive node
        // ZWaveMessagePayloadTransaction nonceGet = securityTx.buildSecurityNonceGet();
        // securityRx.handleSecurityNonceGet(nonceGet, 0);
        //
        // // We should have captured the nonce report
        // assertNotNull(argumentRx.getValue());
        //
        // // Get a nonce from the receiver and pass it to the transmitter
        // securityTx.handleSecurityNonceReport(argumentRx.getValue(), 0);
        // assertTrue(securityTx.isNonceAvailable());
        //
        // // Now encapsulate our message
        // byte[] request = securityTx.getSecurityMessageEncapsulation(payload);
        //
        // byte[] response = securityRx.getSecurityMessageDecapsulation(request);
        //
        // assertTrue(Arrays.equals(payload, response));
    }

    private static ZWaveSecurity2CommandClass buildZWaveSecurity2CommandClass() {
        CryptoInitTestHelper.initCryptoForTesting(null, null);
        // Mocks
        byte nodeId = 0x01;
        byte[] payload = { nodeId, 2, (byte) CommandClass.COMMAND_CLASS_SECURITY.getKey(),
                CommandClassSecurityV1.SECURITY_COMMANDS_SUPPORTED_GET, };
        ZWaveNode nodeTx = Mockito.mock(ZWaveNode.class);
        Mockito.when(nodeTx.getNodeId()).thenReturn(0x02);
        ZWaveController controllerTx = Mockito.mock(ZWaveController.class);
        Mockito.when(controllerTx.getOwnNodeId()).thenReturn(0x01);

        ZWaveNode nodeRx = Mockito.mock(ZWaveNode.class);
        Mockito.when(nodeRx.getNodeId()).thenReturn(0x01);
        ZWaveController controllerRx = Mockito.mock(ZWaveController.class);
        Mockito.when(controllerRx.getOwnNodeId()).thenReturn(0x02);
        ArgumentCaptor<ZWaveCommandClassTransactionPayload> argumentRx = ArgumentCaptor
                .forClass(ZWaveCommandClassTransactionPayload.class);
        Mockito.doNothing().when(controllerRx).enqueue(argumentRx.capture());
        Mockito.when(controllerRx.getSecurityKeys()).thenReturn(CryptoInitTestHelper.keys);

        ZWaveEndpoint endpoint = Mockito.mock(ZWaveEndpoint.class);
        ZWaveSecurity2CommandClass security2CC = new ZWaveSecurity2CommandClass(nodeRx, controllerRx, endpoint);
        return security2CC;
    }
}
