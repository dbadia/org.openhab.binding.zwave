/**
 * Copyright (c) 2010-2018 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zwave.internal.protocol.commandclass.impl;

import static org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2EncapsulationExtensionType.parse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openhab.binding.zwave.internal.protocol.commandclass.ZWaveCommandClass;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.ZwaveSecurity2KexData;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2BitmaskEnumType;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2ECDHProfile;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2EncapsulationExtensionType;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2FailType;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2KexScheme;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2KeyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class to implement the Z-Wave command class <b>COMMAND_CLASS_SECURITY_2</b> version <b>1</b>.<br>
 *
 * Command Class Security 2<br>
 *
 * This class provides static methods for processing received messages (message handler) and
 * methods to get a message to send on the Z-Wave network.<br>
 *
 * @author Dave Badia
 */
public class CommandClassSecurity2V1 {
    static final Logger logger = LoggerFactory.getLogger(CommandClassSecurity2V1.class);

    /**
     * Integer command class key for COMMAND_CLASS_SECURITY_2
     */
    public final static int COMMAND_CLASS_KEY = ZWaveCommandClass.CommandClass.COMMAND_CLASS_SECURITY_2.getKey();

    // TODO: document these if we don't auto generate
    public final static int SECURITY_2_COMMANDS_NONCE_GET = 0x01; // TODO: SECURITY_2_NONCE_GET match spec
    public final static int SECURITY_2_COMMANDS_NONCE_REPORT = 0x02; // TODO: SECURITY_2_NETWORK_KEY_REPORT
    public static final int SECURITY_2_MESSAGE_ENCAPSULATION = 0x03; // TODO: COMMAND not message
    public final static int KEX_GET = 0x04;
    public final static int KEX_REPORT = 0x05;
    public final static int KEX_SET = 0x06;
    public final static int SECURITY_2_KEX_FAIL = 0x07;
    public final static int PUBLIC_KEY_REPORT = 0x08;
    public final static int SECURITY_2_NETWORK_KEY_GET = 0x09;
    public final static int SECURITY_2_NETWORK_KEY_REPORT = 0x0A;
    public final static int SECURITY_2_NETWORK_KEY_VERIFY = 0x0B;

    private final static Map<Class<? extends Enum>, Map<Integer, ZWaveSecurity2BitmaskEnumType>> ENUM_LOOKUP_TABLE_CACHE = new ConcurrentHashMap<>();

    public static byte[] buildKexGet() {
        logger.debug("Creating command message SECURITY_2_COMMANDS_NONCE_GET version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(SECURITY_2_COMMANDS_NONCE_GET);

        return outputData.toByteArray();
    }

    public static byte[] buildKexSet(ZwaveSecurity2KexData kexSetData) {
        logger.debug("Creating command message SECURITY_2_KEX_SET version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(KEX_SET);

        // Echo[0] - CC:009F.01.06.11.00D The including node MUST set this flag to ‘0’.
        boolean echoFlag = false;
        writeKexData(outputData, echoFlag, kexSetData);
        return outputData.toByteArray();
    }

    /**
     * KEX_SET and KEX_REPORT contain identical fields
     */
    private static void writeKexData(ByteArrayOutputStream outputData, boolean echoFlag,
            ZwaveSecurity2KexData kexData) {
        // bitmask (1 byte)
        BitSet bitmask = new BitSet(8); // All zeros - all off

        // ECHO[0]
        if (echoFlag) {
            bitmask.set(0);
        }
        // CSA[1]
        if (kexData.isClientSideAuthentication()) {
            bitmask.set(1);
        }
        writeBitmask(bitmask, outputData);

        // Supported/Selected KEX Scheme (1 byte)
        writeBitmask(buildBitmask(kexData.getKexSchemesList()), outputData);

        // Supported/Selected ECDH Profile (1 byte)
        writeBitmask(buildBitmask(kexData.getEcdhProfileList()), outputData);

        // Granted/Requested Keys (1 byte)
        writeBitmask(buildBitmask(kexData.getKeyTypeList()), outputData);
    }

    public static byte[] buildNetworkKeyReport(ZWaveSecurity2KeyType keyType, byte[] keybytes) {
        logger.debug("Creating command message SECURITY_2_NETWORK_KEY_REPORT version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(SECURITY_2_NETWORK_KEY_REPORT);

        // Granted Key (1 byte)
        ZWaveSecurity2KeyType[] keysToSendArray = new ZWaveSecurity2KeyType[] { keyType };
        writeBitmask(buildBitmask(keysToSendArray), outputData);

        // Network key (16 bytes)
        if (keybytes.length != 16) {

        }

        return outputData.toByteArray();
    }

    public static Map<String, Object> handleSecurity2KexGet(byte[] payload) {
        logger.debug("Parsing SECURITY_2_KEX_GET");
        Map<String, Object> responseTable = new ConcurrentHashMap<String, Object>();

        // Parse 'Requested Key' (1 byte)
        List<ZWaveSecurity2KeyType> requestedKeysList = parseBitMask(payload[5], ZWaveSecurity2KeyType.class,
                ZWaveSecurity2KeyType.class);
        responseTable.put("REQUESTED_KEYS", requestedKeysList);

        // Return the map of processed response data;
        return responseTable;
    }

    /**
     * The fields for KEX_SET and KEX_REPORT are the same, so we use one method to parse both
     */
    public static Map<String, Object> handleSecurity2KexReportOrKexSet(byte[] payload, boolean isReport) {
        if (isReport) {
            logger.debug("Parsing SECURITY_2_KEX_REPORT");
        } else {
            logger.debug("Parsing SECURITY_2_KEX_SET");
        }
        Map<String, Object> responseTable = new ConcurrentHashMap<String, Object>();

        // Parse 'Echo'
        BitSet bitSet = BitSet.valueOf(new byte[] { payload[2] });
        logger.debug("Parsing SECURITY_2_KEX_REPORT echo = " + bitSet.get(0)); // TODO: LOG remove or trace
        responseTable.put("ECHO", bitSet.get(0));

        // Parse 'Request CSA'
        logger.debug("Parsing SECURITY_2_KEX_REPORT CSA = " + bitSet.get(1)); // TODO: LOG remove or trace
        responseTable.put("CLIENT_SIDE_AUTHENTICATION", bitSet.get(1));

        // Parse Supported KEX Schemes
        // CC:009F.01.05.11.00B All other bits are reserved and MUST be set to zero by a sending node.
        List<ZWaveSecurity2KexScheme> supportedKexSchemesList = parseBitMask(payload[3], ZWaveSecurity2KexScheme.class,
                ZWaveSecurity2KexScheme.class);
        responseTable.put("SUPPORTED_KEX_SCHEMES", supportedKexSchemesList);

        // Parse 'Supported ECDH Profiles' (1 byte)
        List<ZWaveSecurity2ECDHProfile> supportedECDHProfilesList = parseBitMask(payload[4],
                ZWaveSecurity2ECDHProfile.class, ZWaveSecurity2ECDHProfile.class);
        responseTable.put("SUPPORTED_ECDH_PROFILES", supportedECDHProfilesList);

        // Parse 'Requested Keys' (1 byte)
        List<ZWaveSecurity2KeyType> requestedKeysList = parseBitMask(payload[5], ZWaveSecurity2KeyType.class,
                ZWaveSecurity2KeyType.class);
        responseTable.put("REQUESTED_KEYS", requestedKeysList);

        // Return the map of processed response data;
        return responseTable;
    }

    public static Map<String, Object> handlePublicKeyReport(byte[] payload) {
        logger.debug("Parsing PUBLIC_KEY_REPORT");
        Map<String, Object> responseTable = new ConcurrentHashMap<String, Object>();

        // Parse 'Including node'
        BitSet bitSet = BitSet.valueOf(new byte[] { payload[0] });
        responseTable.put("INCLUDING_NODE", bitSet.get(0));

        // ECDH Public key
        byte[] publicKeyBytes = new byte[payload.length - 1];
        System.arraycopy(payload, 1, publicKeyBytes, 0, payload.length - 1);
        responseTable.put("NODE_PUBLIC_KEY_BYTES", publicKeyBytes);

        return responseTable;
    }

    public static byte[] buildPublicKeyReport(byte[] ourPublicKeyBytes) throws IOException {
        logger.debug("Creating command message PUBLIC_KEY_REPORT version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(PUBLIC_KEY_REPORT);

        // bitmask (1 byte)
        BitSet bitmask = new BitSet(8); // All zeros
        bitmask.set(0); // CC:009F.01.08.11.003 When sent by the including node this flag MUST be set to ‘1’.
        writeBitmask(bitmask, outputData);

        outputData.write(ourPublicKeyBytes);

        return outputData.toByteArray();
    }

    public static Map<String, Object> handleNonceGet(byte[] payload) {
        logger.debug("Parsing NONCE_GET");
        Map<String, Object> responseTable = new ConcurrentHashMap<String, Object>();

        int sequenceNumber = payload[0] & 0xFF;
        responseTable.put("SEQUENCE_NUMBER", sequenceNumber);

        return responseTable;
    }

    public static byte[] buildNonceReport(int sequenceNumber, boolean mpanOutOfSync, boolean spanOutOfSync,
            byte[] reiBytes) throws IOException {
        logger.debug("Creating command message SECURITY_2_COMMANDS_NONCE_REPORT version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(SECURITY_2_COMMANDS_NONCE_REPORT);

        // Sequence Number (1 byte)
        outputData.write(sequenceNumber);

        // 8 bits: MOS SOS Reserved
        BitSet bitmask = new BitSet(8); // All zeros
        if (mpanOutOfSync) {
            bitmask.set(0);
        }
        if (spanOutOfSync) {
            bitmask.set(1);
        }
        writeBitmask(bitmask, outputData);

        // CC:009F.01.02.11.00F
        // If the SOS flag is set to ‘0’, the REI field MUST NOT be included in the command
        // If the SOS flag is set to ‘1’, the REI field MUST be included in the command.
        if (spanOutOfSync) {
            outputData.write(reiBytes);
        } else if (reiBytes != null) {
            logger.warn("buildNonceReport was passed SOS false but with an REI.  REI not sent");
        }

        return outputData.toByteArray();
    }

    /**
     * Step 18. A->B : KEX Report (echo) : The KEX Report Command received from Node B in step 3 is confirmed via the
     * temporary secure channel.
     */
    public static byte[] buildKexReport(ZwaveSecurity2KexData kexReportDataFromNode) {
        logger.debug("Creating command message KEX_REPORT version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(KEX_REPORT);

        boolean echoFlag = true;
        writeKexData(outputData, echoFlag, kexReportDataFromNode);

        return outputData.toByteArray();
    }

    /**
     * 3.1.7.4 Security 2 KEX Fail Command
     *
     * @param CC:009F.01.07.11.002 KEX Fail Type (1 byte) This field MUST advertise one of the types defined in Table 16
     */
    public static byte[] buildFail(ZWaveSecurity2FailType failType) {
        logger.debug("Creating command message SECURITY_2_COMMANDS_FAIL version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(SECURITY_2_KEX_FAIL);

        outputData.write(failType.toByte());
        return outputData.toByteArray();
    }

    public static Map<String, Object> handleSecurity2DecapsulationUnencyptedPortions(byte[] payload) {
        logger.debug("Parsing SECURITY_2_MESSAGE_ENCAPSULATION");
        Map<String, Object> responseTable = new ConcurrentHashMap<String, Object>();

        // Variable length fields exist, so track the offset
        int msgOffset = 2;

        // Parse 'Sequence'
        responseTable.put("SEQUENCE", new Integer(payload[msgOffset++]));
        msgOffset += 1;

        // Parse 'Extension' and 'Encrypted Extension'
        BitSet bitSet = BitSet.valueOf(new byte[] { payload[msgOffset++] });
        boolean hasExtension = bitSet.get(0);
        responseTable.put("HAS_EXTENSION", hasExtension);
        boolean hasEncryptedExtension = bitSet.get(1);
        responseTable.put("HAS_ENCRYPTED_EXTENSION", hasEncryptedExtension);
        logger.debug("Parsing SECURITY_2_MESSAGE_ENCAPSULATION extension={}, encrypted extension={}" + hasExtension,
                hasEncryptedExtension);
        msgOffset++;

        // Parse the Extensions if they are present
        ByteArrayOutputStream extensionBaos = new ByteArrayOutputStream();
        while (hasExtension) {
            int length = payload[msgOffset++];
            byte multiByte = payload[msgOffset++];
            bitSet = BitSet.valueOf(new byte[] { multiByte });
            boolean critical = bitSet.get(6);
            hasExtension = bitSet.get(7); // More to follow
            int typebyte = multiByte & 0x3F;
            ZWaveSecurity2EncapsulationExtensionType type = parse(typebyte);
            if (type.isEncrypted()) {
                logger.warn(
                        "Encapsulation Extension Type {} should have been encrypted, but wasn't.  Encapsulation extension ignored.",
                        type);
            } else {
                switch (type) {
                    // 3.6.5.3.3.1 Valid Extensions and Encrypted Extensions
                    case SPAN:
                        // Parse the SPAN Extension 3.6.5.3.3.1.1
                        if (length != 18) {
                            logger.error(
                                    "Invalid length for SPAN extension, expected=18, found={}.  Encapsulation extension ignored.",
                                    length);
                            // SPAN has the sender nonce, without it, we can't decrypt the payload so we stop
                            return null; // fail silently since this is not in Table 11, Security 2 bootstrapping
                        } else {
                            byte[] senderEntrophyInput = new byte[16];
                            System.arraycopy(payload, msgOffset, senderEntrophyInput, 0, 16);
                            msgOffset += 16;
                            responseTable.put("SPAN_SENDER_ENTROPHY", senderEntrophyInput);
                        }
                        break;
                    case MGRP:
                    case MOS:
                        if (critical) {
                            // CC:009F.01.03.11.008 A receiving node MUST discard the entire command if this flag is set
                            // to ‘1’ and the Type field advertises a value that the receiving node does not support
                            logger.error("Encapsulation extension type={} is not supported and is marked as critical.  "
                                    + "Dropping entire message", type);
                            return null; // fail silently since this is not in Table 11, Security 2 bootstrapping
                        } else {
                            logger.error("Encapsulation extension type={} is not supported.  Skipping", type);
                        }
                    default:
                        if (critical) {
                            // CC:009F.01.03.11.008 A receiving node MUST discard the entire command if this flag is set
                            // to ‘1’ and the Type field advertises a value that the receiving node does not support
                            logger.error("Encapsulation extension type={} is invalid and is marked as critical.  "
                                    + "Dropping entire message", type);
                            return null; // fail silently since this is not in Table 11, Security 2 bootstrapping
                        } else {
                            logger.warn("Invalid encapsulation extension type={}.  Skipping", type);
                            // TODO: check OH code standards, should thsi be warn?
                        }
                        break;
                }
            }
        }
        responseTable.put("EXTENSION_BYTES", extensionBaos.toByteArray());
        int encryptedLength = payload.length - msgOffset;
        byte[] encryptedBytes = new byte[encryptedLength];
        System.arraycopy(payload, msgOffset, encryptedBytes, 0, encryptedLength);
        responseTable.put("ENCRYPTED_BYTES", hasEncryptedExtension);
        return responseTable;
    }

    // TODO: move this to a test case, test each enu
    public static void main(String[] args) {
        try {
            List<ZWaveSecurity2ECDHProfile> listEcdhProfileList = parseBitMask((byte) 255,
                    ZWaveSecurity2ECDHProfile.class, ZWaveSecurity2ECDHProfile.class);
            System.out.println(listEcdhProfileList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void writeBitmask(BitSet bitSet, ByteArrayOutputStream outputData) {
        byte[] bytes = bitSet.toByteArray();
        byte result = 0;
        // If all bits were set to zero, we get an empty array
        if (bytes.length > 0) {
            result = bytes[0];
        }
        outputData.write(result);
    }

    /**
     * Parses a byte into a bitmask, then returns a List of the bitmask enums which were set
     *
     * @param toParse            the byte to parse
     * @param enumClass          The enumeration class which implements ZWaveSecurity2BitmaskEnumType
     * @param enumClassAsBitmask the same argument as enumClass, required for proper generics handling
     * @return list of the corresponding bitmask enums which were set on the given byte
     */
    private static <E extends Enum<E>, B extends ZWaveSecurity2BitmaskEnumType> List<B> parseBitMask(byte toParse,
            Class<E> enumClass, Class<B> enumClassAsBitmask) {
        BitSet bitSet = BitSet.valueOf(new byte[] { toParse });
        Map<Integer, ZWaveSecurity2BitmaskEnumType> bitMaskLookupTable = ENUM_LOOKUP_TABLE_CACHE.get(enumClass);
        if (bitMaskLookupTable == null) {
            // Not cached, build the table
            bitMaskLookupTable = new ConcurrentHashMap<>();
            for (Enum<E> enumVal : enumClass.getEnumConstants()) {
                if (enumVal instanceof ZWaveSecurity2BitmaskEnumType) {
                    ZWaveSecurity2BitmaskEnumType bitmaskEnumType = (ZWaveSecurity2BitmaskEnumType) enumVal;
                    bitMaskLookupTable.put(bitmaskEnumType.getBitPosition(), bitmaskEnumType);
                } else {
                    throw new IllegalStateException(
                            "Programmatic error, " + enumVal + " does not implement ZWaveSecurity2BitmaskEnumType");
                }
            }
            ENUM_LOOKUP_TABLE_CACHE.put(enumClass, bitMaskLookupTable);
        }
        // Parse the byte into it's corresponding enum bits
        List<B> parsedList = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            boolean set = bitSet.get(i);
            if (set) {
                B enumValue = (B) bitMaskLookupTable.get(i);
                if (enumValue == null) {
                    logger.error("Unsupported bit set on " + enumClass + " at position" + i);
                } else {
                    parsedList.add(enumValue);
                }
            }
        }
        return parsedList;
    }

    private static <E extends Enum<E>, B extends ZWaveSecurity2BitmaskEnumType> BitSet buildBitmask(
            B... bitmaskValuesToInclude) {
        BitSet bitmask = new BitSet();
        for (B aValue : bitmaskValuesToInclude) {
            bitmask.set(aValue.getBitPosition());
        }
        return bitmask;
    }

    private static <E extends Enum<E>, B extends ZWaveSecurity2BitmaskEnumType> BitSet buildBitmask(
            List<B> bitmaskValuesToInclude) {
        BitSet bitmask = new BitSet();
        for (B aValue : bitmaskValuesToInclude) {
            bitmask.set(aValue.getBitPosition());
        }
        return bitmask;
    }

    private static BitSet byteToBitSet(byte b) {
        int n = 8;
        final BitSet bitSet = new BitSet(n);
        while (n-- > 0) {
            boolean isSet = (b & 0x80) != 0;
            bitSet.set(n, isSet);
            b <<= 1;
        }
        return bitSet;
    }
}
