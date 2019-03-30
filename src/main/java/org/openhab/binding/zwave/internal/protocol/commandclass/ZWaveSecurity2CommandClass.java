/**
 * Copyright (c) 2010-2018 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zwave.internal.protocol.commandclass;

import static org.openhab.binding.zwave.internal.protocol.commandclass.impl.CommandClassSecurity2V1.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.ZWaveCommandClassPayload;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveEndpoint;
import org.openhab.binding.zwave.internal.protocol.ZWaveMessagePayloadTransaction;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.ZWaveTransaction.TransactionPriority;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.CommandClassSecurity2V1;
import org.openhab.binding.zwave.internal.protocol.initialization.ZWaveNodeInitStageAdvancer;
import org.openhab.binding.zwave.internal.protocol.security.ZWaveCryptoException;
import org.openhab.binding.zwave.internal.protocol.security.ZWaveCryptoOperations;
import org.openhab.binding.zwave.internal.protocol.security.ZWaveProtocolViolationException;
import org.openhab.binding.zwave.internal.protocol.security.ZwaveKexData;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2ECDHProfile;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2EncapsulationExtensionType;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2FailType;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2KexScheme;
import org.openhab.binding.zwave.internal.protocol.security.enums.ZWaveS2KeyType;
import org.openhab.binding.zwave.internal.protocol.transaction.ZWaveCommandClassTransactionPayload;
import org.openhab.binding.zwave.internal.protocol.transaction.ZWaveCommandClassTransactionPayloadBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.EvictingQueue;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

/**
 * ZWave security 2 command class v1
 *
 * <p/>
 * <b>Implemenation Notes: (still spec compliant)</b>
 * <li>A. The spec allows for devices to be issued more than one of ZWaveSecurity2KeyType. But, we only issue one of
 * ZWaveSecurity2KeyType to each node because:
 * A1) The encapsulation frame has no indicator of which key is in use so we don't know which key the device used (or
 * the
 * controller should use) during encapsulation/decapsulation. We could use trial and error but that is highly
 * inefficient
 *
 * <li>B. The S0 security class (Table 13) is not implemented because nodes can just use COMMAND_CLASS_SECURITY instead
 * of this class.
 * The spec is ambiguous about the S0 security class in the the following ways:
 * B1) Why a class wanting S0 would send the Security2 command instead of the original Security command (which already
 * supports S0)?
 * B2) How the keys are exchanged? The flows in details in 3.5 look identical to that of COMMAND_CLASS_SECURITY but
 * CC:009F.01.00.11.037 shows use of ECDH Temporary Key
 * </li>
 * <p/>
 * <li></li>
 *
 * <p/>
 * <b>Spec compliance issues/ambiguities:</b>
 * <li>Is the inclusion controller a "supporting always listening node"? If yes, we must store at least 5 SPAN entries
 * for each node CC:009F.01.00.11.0A0</li>
 * <li>CC:009F.01.00.11.017.11.0A0 requires we use a hardware source of entropy to see our RNG. While some chipsets do
 * support this, we have no way of knowing if we are running on such hardware.</li>
 *
 * @author Dave Badia
 */
@XStreamAlias("COMMAND_CLASS_SECURITY_2")
public class ZWaveSecurity2CommandClass extends ZWaveCommandClass implements ZWaveSecurityCommand {
    private static final int ENTROPHY_INPUT_SIZE = 16;

    public static final byte[] CKDF_TEMP_EXTRACT_CONSTANT = new byte[16];

    /*
     * ConstNonce = 0x26 repeated 16 times
     */
    public static final byte[] CONST_NONCE_CONSTANT = new byte[16];

    /*
     * ConstEntropyInput = 0x88 repeated 15 times
     */
    public static final byte[] CONST_ENTROPHY_INPUT_CONSTANT = new byte[16];

    private static final Random INSECURE_RANDOM = new Random();

    private static final Logger logger = LoggerFactory.getLogger(ZWaveSecurity2CommandClass.class);

    private static final long TEN_SECONDS_MILLIS = TimeUnit.SECONDS.toMillis(10);

    private static ZWaveCryptoOperations cryptoOperations;

    private static final ExecutorService BACKGROUND_EXECUTOR_SERVICE = Executors.newCachedThreadPool();

    @XStreamOmitField
    private final byte[] homeId;

    @XStreamOmitField
    private final int controllerNodeId;

    @XStreamOmitField
    private ZwaveKexData kexSetDataSentToNode = null;

    @XStreamOmitField
    // We also use this object for wait/notify
    private AtomicBoolean ourTempEcdhKeyPairGenerationInProgress = new AtomicBoolean(false);

    @XStreamOmitField
    private volatile KeyPair ourTempEcdhKeyPair;

    /**
     * The temporary AES key used during inclusion. Must be set to null once permanent keys are in use
     */
    @XStreamOmitField
    private SecretKey tempAesCcmKey;
    /**
     * The temporary Personalization String used during inclusion. Must be set to null once permanent keys are in use
     */
    @XStreamOmitField
    private byte[] tempPersonalizationString;

    @XStreamOmitField
    ZwaveKexData kexReportDataFromNode;

    @XStreamOmitField
    private byte[] deviceEcdhPublicKeyBytes;

    /**
     * Track which keys have been assigned to this node
     */
    private List<ZWaveS2KeyType> grantedKeysList;

    @XStreamOmitField
    private List<ZWaveS2KeyType> keysThatNeedToBeSent;

    /**
     * CC:009F.01.00.11.02D A receiving node MUST use the Sequence Number field in the Nonce Get, Nonce Report and
     * Message Encapsulation commands for duplicate detection.
     *
     * The spec requires this counter be incremented each time the node sends us a message. But the field is only a
     * byte and starts with a random value on each node restart. Therefore, instead of keeping a single value and having
     * to deal with rollover logic, we keep a fixed length queue and just see if a new value exists in the queue or not
     *
     * @XStreamOmitField as we have no idea how long the controller node has been offline and how many messages the
     *                   node while the controller was offline
     */
    @XStreamOmitField
    private Queue<Integer> duplicateSequenceCounterQueue = EvictingQueue.create(5);

    // @formatter:off
    /**
     * There is no AtomicByte class, so we use AtomicInteger and cast to byte as needed.
     *
     * This is as suggested in the API docs for the java.util.concurrent package:
     *      Additionally, classes are provided only for those types that are commonly useful in intended applications.
     *      For example, there is no atomic class for representing byte. In those infrequent cases where you would like to do
     *      so, you can use an AtomicInteger to hold byte values, and cast appropriately
     */
    // @formatter:on
    private AtomicInteger outgoingSequenceCounter = null;

    /**
     * CC:009F.01.00.11.01B Singlecast
     * The Receiver uses its PRNG to generate a random 16-byte Nonce, store it in the SPAN table and send it in a Nonce
     * Report to the Sender, with the Singlecast Out of Sync (SOS) flag set, to indicate that the frame contains a
     * Receiver’s Entropy Input (REI).
     * a. The Sender stores the Receiver’s Entropy Input in the SPAN table in the entry matching the the receiver’s
     * NodeID.
     */
    @XStreamOmitField
    private byte[] lastReceiverEntropyInputNoneSentToNode = null;

    @XStreamOmitField
    private Long lastNonceGetReceived = Long.valueOf(0); // TODO: delete

    /*
     * has to be non-null by default so we can synchronize on it
     */
    @XStreamOmitField
    private Long lastResponseQueuedAt = Long.valueOf(0);

    /*
     * default must not be one of CommandClassSecurity2V1
     */
    @XStreamOmitField
    private int lastResponseQueuedCommandClass = -1;

    private SecureRandom inboundSpan = null;
    private SecureRandom outboundSpan = null;

    /**
     * Flag that is periodically checked by {@link ZWaveNodeInitStageAdvancer} to see if secure pairing should continue
     */
    @XStreamOmitField
    private AtomicBoolean continueSecurePairing = new AtomicBoolean(true);

    /**
     * Used in conjunction with {@link #continueSecurePairing}. When continueSecurePairing == true,
     * ZWaveNodeInitStageAdvancer must check this field to see if a FAIL command should be sent to the node
     */
    @XStreamOmitField
    private volatile ZWaveProtocolViolationException protocolViolationException = null;

    /**
     * At the moment, the spec defines only 1 valid profile, so it is safe to hardcode it
     */
    @XStreamOmitField
    private volatile ZWaveS2ECDHProfile ecdhProfileInUse = ZWaveS2ECDHProfile.Curve25519;

    static {
        byte aByte = 0x33 & 0xFF;
        Arrays.fill(CKDF_TEMP_EXTRACT_CONSTANT, aByte);

        aByte = 0x26 & 0xFF;
        Arrays.fill(CONST_NONCE_CONSTANT, aByte);

        aByte = (byte) (0x88 & 0xFF);
        Arrays.fill(CONST_ENTROPHY_INPUT_CONSTANT, aByte);
    }

    /**
     * Creates a new instance of the ZWaveSecurity2CommandClass class.
     *
     * @param node
     *                       the node this command class belongs to
     *                       the controller to use
     * @param controller
     * @param endpoint
     *                       the endpoint this Command class belongs to
     */
    public ZWaveSecurity2CommandClass(ZWaveNode node, ZWaveController controller, ZWaveEndpoint endpoint) {
        super(node, controller, endpoint);
        this.controllerNodeId = controller.getOwnNodeId();
        this.homeId = ByteBuffer.allocate(4).putInt(controller.getHomeId()).array();
        if (cryptoOperations == null) {
            throw new IllegalStateException(
                    "initializeCrypto() must be called prior to " + getClass().getSimpleName() + " constructor");
        }
    }

    @Override
    public CommandClass getCommandClass() {
        return CommandClass.COMMAND_CLASS_SECURITY_2;
    }

    public static void initializeCrypto() {
        if (cryptoOperations == null) {
            cryptoOperations = ZWaveCryptoOperations.getInstance();
        }
    }

    /**
     * This command is used by an including node to query the joining node for supported KEX Schemes and ECDH profiles
     * as well as which network keys the joining node intends to request.
     * This command MUST be ignored if Learn Mode is disabled. The KEX Report Command MUST be returned in response to
     * this command if Learn Mode is enabled. This command MUST NOT be issued via multicast addressing.
     * A receiving node MUST NOT return a response if this command is received via multicast addressing. The Z-Wave
     * Multicast frame, the broadcast NodeID and the Multi Channel multi-End Point destination are are all considered
     * multicast addressing methods.
     *
     * @return
     */
    public ZWaveMessagePayloadTransaction buildKexGetMessage() {
        ZWaveCommandClassTransactionPayload payload = new ZWaveCommandClassTransactionPayloadBuilder(
                getNode().getNodeId(), CommandClassSecurity2V1.buildKexGet())
                        .withExpectedResponseCommand(CommandClassSecurity2V1.KEX_REPORT)
                        .withPriority(TransactionPriority.Immediate).build();
        return payload;
    }

    /**
     * Step 3. B->A : KEX Report : Sent as response to the KEX Get command
     * see CC:009F.01.00.11.05
     */
    @SuppressWarnings("unchecked")
    @ZWaveResponseHandler(id = CommandClassSecurity2V1.KEX_REPORT, name = "KEX_REPORT")
    public void handleSecurity2KexReport(ZWaveCommandClassPayload payload, int endpoint) {
        logger.debug("NODE {}: SECURITY_2_INC State=KEX_REPORT_RECEIVED", getNode().getNodeId());
        // TODO: either add everywhere or just remove all b/c they are already shown in th elog tool?
        Map<String, Object> response = CommandClassSecurity2V1
                .handleSecurity2KexReportOrKexSet(payload.getPayloadBuffer(), true);

        Boolean clientSideAuthenticationBit = (Boolean) response.get("CLIENT_SIDE_AUTHENTICATION");
        Boolean echoBit = (Boolean) response.get("ECHO");

        List<ZWaveS2KexScheme> supportedKexSchemesList = (List<ZWaveS2KexScheme>) response
                .get("SUPPORTED_KEX_SCHEMES");
        List<ZWaveS2ECDHProfile> supportedEcdhProfilesList = (List<ZWaveS2ECDHProfile>) response
                .get("SUPPORTED_ECDH_PROFILES");
        List<ZWaveS2KeyType> requestedKeyTypeList = (List<ZWaveS2KeyType>) response.get("REQUESTED_KEYS");

        logger.debug("NODE {}: requestedKeyTypeList {}", getNode().getNodeId(), requestedKeyTypeList);
        ZwaveKexData currentKexReportData = null;
        try {
            currentKexReportData = validateKexReport(clientSideAuthenticationBit, echoBit, supportedKexSchemesList,
                    supportedEcdhProfilesList, requestedKeyTypeList);
        } catch (ZWaveProtocolViolationException e) {
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=SPEC_VIOLATION {}", getNode().getNodeId(),
                    e.getMessage());
            continueSecurePairing.set(false);
            protocolViolationException = e;
            return;
        }

        if (getNode().getSecurity2CommandClass() == null && kexReportDataFromNode != null
                || getNode().getSecurity2CommandClass() != null && kexReportDataFromNode == null) {
            logger.error(
                    "NODE {}: SECURITY_2_INC State=FAILED, Reason=PROGRAMMATIC_ERROR security state out of sync: sec2cc={} kexReportDataFromNode={}",
                    getNode().getNodeId(), getNode().getSecurity2CommandClass(), kexReportDataFromNode);
            continueSecurePairing.set(false);
            return;
        }
        boolean joiningNodeMode = getNode().getSecurity2CommandClass() == null && kexReportDataFromNode == null;
        if (joiningNodeMode) {
            // CC:009F.01.05.11.008 The including node MUST return a KEX Set Command in response to this command if
            // the “Echo” flag is set to ‘0’ and is performing S2 Bootstrapping.
            if (echoBit == true) {
                // TODO: remove these calls from this method and move up in shouldCOntinue logic in advancer
                // controller.notifyEventListeners(
                // new ZWaveInclusionEvent(ZWaveInclusionState.SecureIncludeFailed, node.getNodeId()));
                logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=KEX_REPORT_ECHO_1", getNode().getNodeId());
                continueSecurePairing.set(false);
                return;
            }
        }
        this.kexReportDataFromNode = currentKexReportData;
    }

    private ZwaveKexData validateKexReport(Boolean csaBit, Boolean echoBit,
            List<ZWaveS2KexScheme> supportedKexSchemesList,
            List<ZWaveS2ECDHProfile> supportedEcdhProfilesList, List<ZWaveS2KeyType> requestedKeyTypeList)
            throws ZWaveProtocolViolationException {
        // request CSA bit
        if (csaBit == null) {
            throw new ZWaveProtocolViolationException("KEX_REPORT csa bit was null");
        }
        // TODO: validate CSA bit as follows
        /**
         * CC:009F.01.05.11.019 This flag MUST be set to 0 if none of the S2 Authenticated and S2 Access Control
         * Security Classes are requested
         *
         * CC:009F.01.05.11.01A This flag MUST be set to 0 if the sending node has a DSK label printed on itself.
         *
         * CC:009F.01.05.11.01B This flag MUST be set to 1 by a node only if it has been OTA firmware upgraded to
         * support S2 and requests S2 Authenticated or S2 Access Control Security Class
         */

        // ECHO bit
        if (echoBit == null) {
            throw new ZWaveProtocolViolationException("KEX_REPORT echo bit was null");
        }

        // Supported KEX Schemes
        // CC:009F.01.05.11.00F A node supported the Security 2 Command Class MUST support KEX Scheme 1.
        if (supportedKexSchemesList.isEmpty() || !supportedKexSchemesList.contains(ZWaveS2KexScheme._1)) {
            throw new ZWaveProtocolViolationException(
                    "KEX_REPORT No common KEX schemes found " + supportedKexSchemesList,
                    ZWaveS2FailType.KEX_FAIL_KEX_SCHEME);
        }

        // Supported ECDH profiles
        // CC:009F.01.05.11.014 Curve25519 MUST be supported by a node supporting the Security 2 Command Class.
        if (supportedEcdhProfilesList.isEmpty()
                || !supportedEcdhProfilesList.contains(ZWaveS2ECDHProfile.Curve25519)) {
            throw new ZWaveProtocolViolationException(
                    "KEX_REPORT No common ECDH profiles found in " + supportedEcdhProfilesList,
                    ZWaveS2FailType.KEX_FAIL_KEX_CURVES);
        }

        // Requested keys
        // CC:009F.01.05.11.018 A node supporting the Security 2 Command Class MUST support at least one Key. A
        // node may support multiple keys.
        if (requestedKeyTypeList.isEmpty()) {
            throw new ZWaveProtocolViolationException("KEX_REPORT No keys requested" + requestedKeyTypeList,
                    ZWaveS2FailType.KEX_FAIL_KEX_KEY);
        }

        // Everything checked out, return the holder object
        return new ZwaveKexData(csaBit, supportedKexSchemesList, supportedEcdhProfilesList,
                requestedKeyTypeList);

    }

    /**
     * Step 5. A->B : KEX Set : The KEX Set Command contains parameters selected by Node A. The list of class keys
     * MAY be reduced to a subset of the list that was requested in the previous KEX Report from Node B.
     * see CC:009F.01.00.13.008
     *
     * 3.6.7.3 Security 2 KEX Set Command
     * <p/>
     * 1) During initial key exchange this command is used by an including node to grant network keys to a joining node.
     * The joining node subsequently requests the granted keys once a temporary secure channel has been established. The
     * including node MUST send the command non-securely.
     *
     * @return
     */
    public ZWaveMessagePayloadTransaction buildKexSetMessageForInitialKeyExchange(ZwaveKexData kexSetData) {
        this.kexSetDataSentToNode = kexSetData;
        ZWaveCommandClassTransactionPayload payload = new ZWaveCommandClassTransactionPayloadBuilder(
                getNode().getNodeId(), CommandClassSecurity2V1.buildKexSet(kexSetData))
                        .withExpectedResponseCommand(CommandClassSecurity2V1.PUBLIC_KEY_REPORT)
                        .withPriority(TransactionPriority.Immediate).build();
        return payload;
    }

    /**
     * Step 16. B->A : KEX Set (echo) : The KEX Set command received from Node A in step 5 is confirmed via the
     * temporary secure channel.
     * see CC:009F.01.00.11.097
     */
    @SuppressWarnings("unchecked")
    @ZWaveResponseHandler(id = CommandClassSecurity2V1.KEX_SET, name = "KEX_SET")
    public void handleKexSet(ZWaveCommandClassPayload payload, int endpoint) {
        logger.debug("NODE {}: SECURITY_2_INC State=KEX_SET_ECHO_RECEIVED", getNode().getNodeId());
        Map<String, Object> responseTable = CommandClassSecurity2V1
                .handleSecurity2KexReportOrKexSet(payload.getPayloadBuffer(), false);
        // Step 16. B->A : KEX Set (echo) : The KEX Set command received from Node A in step 5 is confirmed via the
        // temporary secure channel.
        // see CC:009F.01.00.11.097
        Boolean echoFlag = (Boolean) responseTable.get("ECHO");
        if (echoFlag == false) {
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=KEX_SET_INVALID echo=0", getNode().getNodeId());
            continueSecurePairing.set(false);
            return;
        }
        Boolean requestCsaFlag = (Boolean) responseTable.get("CLIENT_SIDE_AUTHENTICATION");

        List<ZWaveS2KexScheme> kexSchemesList = (List<ZWaveS2KexScheme>) responseTable
                .get("SUPPORTED_KEX_SCHEMES");
        if (kexSchemesList.size() > 1) {
            // Exactly one bit MUST be set to 1 CC:009F.01.06.11.010
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=KEX_SET_INVALID mutliple kex schemes",
                    getNode().getNodeId());
            continueSecurePairing.set(false);
            return;
        }

        List<ZWaveS2ECDHProfile> ecdhProfilesList = (List<ZWaveS2ECDHProfile>) responseTable
                .get("SUPPORTED_ECDH_PROFILES");
        if (ecdhProfilesList.size() > 1) {
            // Exactly one bit MUST be set to 1 CC:009F.01.06.11.011
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=KEX_SET_INVALID mutliple ecdh profiles",
                    getNode().getNodeId());
            continueSecurePairing.set(false);
            return;
        }

        List<ZWaveS2KeyType> grantedKeyTypeList = (List<ZWaveS2KeyType>) responseTable
                .get("REQUESTED_KEYS");
        logger.debug("NODE {}: grantedKeyTypeList {}", getNode().getNodeId(), grantedKeyTypeList);

        ZwaveKexData kexSetEchoedData = new ZwaveKexData(requestCsaFlag, kexSchemesList,
                ecdhProfilesList, grantedKeyTypeList);
        if (this.kexSetDataSentToNode.equals(kexSetEchoedData) == false) {
            // Exactly one bit MUST be set to 1 CC:009F.01.06.11.011
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=KEX_SET_AUTH_ECHO_MISMATCH",
                    getNode().getNodeId());
            continueSecurePairing.set(false);
            protocolViolationException = new ZWaveProtocolViolationException(
                    "KEX_SET echo did not match transmission", ZWaveS2FailType.KEX_FAIL_AUTH);
            return;
        }

        // Reply with the Kex Report
        getController().enqueueNonce(new ZWaveCommandClassTransactionPayloadBuilder(getNode().getNodeId(),
                CommandClassSecurity2V1.buildKexReport(kexReportDataFromNode))
                        .withPriority(TransactionPriority.Immediate).build());
        synchronized (lastResponseQueuedAt) {
            lastResponseQueuedAt.notify();
        }
    }

    /**
     * TODO
     */
    @ZWaveResponseHandler(id = CommandClassSecurity2V1.PUBLIC_KEY_REPORT, name = "PUBLIC_KEY_REPORT")
    public void handlePublicKeyReport(ZWaveCommandClassPayload payload, int endpoint) {
        logger.debug("NODE {}: SECURITY_2_INC State=PUBLIC_KEY_REPORT_RECEIVED", getNode().getNodeId());
        Map<String, Object> responseTable = CommandClassSecurity2V1.handlePublicKeyReport(payload.getPayloadBuffer());

        // Including node: 1 bit
        Boolean includingNodeFlag = (Boolean) responseTable.get("INCLUDING_NODE");
        if (includingNodeFlag) {
            // CC:009F.01.08.11.006 The including node MUST abort S2 bootstrapping if this flag is set to ‘1’ in a
            // received command
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=SPEC_VIOLOATION INCLUDING_NODE bit was set to 1",
                    getNode().getNodeId());
            continueSecurePairing.set(false);
            return;
        }

        byte[] tempDeviceEcdhPublicKeyBytes = (byte[]) responseTable.get("NODE_PUBLIC_KEY_BYTES");
        // CC:009F.01.00.11.0A7 If authentication is used, the DSK bytes 1..2 MUST be obfuscated by zeros.
        if (tempDeviceEcdhPublicKeyBytes[0] != 0 || tempDeviceEcdhPublicKeyBytes[1] != 0) {
            logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=DSK_BYTES_NOT_OBFUSCATED",
                    getNode().getNodeId());
            continueSecurePairing.set(false);
            return;
        }

        // CC:009F.01.08.11.007 The public key MUST be unique for each node. The length of this field is determined by
        // the chosen ECDH profile. Refer to Table 18.
        this.deviceEcdhPublicKeyBytes = tempDeviceEcdhPublicKeyBytes;
    }

    /**
     * TODO
     */
    public ZWaveMessagePayloadTransaction buildPublicKeyReportMessage(byte[] ourPublicKeyBytes) throws IOException {
        ZWaveCommandClassTransactionPayload payload = new ZWaveCommandClassTransactionPayloadBuilder(
                getNode().getNodeId(), CommandClassSecurity2V1.buildPublicKeyReport(ourPublicKeyBytes))
                        .withExpectedResponseCommand(CommandClassSecurity2V1.SECURITY_2_COMMANDS_NONCE_GET)
                        .withPriority(TransactionPriority.Immediate).build();
        return payload;
    }

    public ZWaveMessagePayloadTransaction buildFailMessage(ZWaveS2FailType failType) {
        return new ZWaveCommandClassTransactionPayloadBuilder(getNode().getNodeId(),
                CommandClassSecurity2V1.buildFail(failType)).build();
    }

    private void sendFailMessage(ZWaveS2FailType failType) {
        getController().enqueue(buildFailMessage(failType));
    }

    /**
     * Extracts the spec Fail Type from the exception when possible, otherwise, return defaultFailType
     *
     * @return the fail type from the Exception (if possible), or the defaultFailType if not
     */
    private ZWaveS2FailType extractFailType(Exception e, ZWaveS2FailType defaultFailType) {
        ZWaveS2FailType failType = defaultFailType;
        if (e instanceof ZWaveProtocolViolationException
                && ((ZWaveProtocolViolationException) e).getFailType().isPresent()) {
            failType = ((ZWaveProtocolViolationException) e).getFailType().get();
        }
        return failType;
    }

    public void generateTemporaryEncryptionKeys(byte[] deviceEcdhPublicKeyBytes) throws ZWaveCryptoException {
        this.deviceEcdhPublicKeyBytes = deviceEcdhPublicKeyBytes;
        byte[] ecdhSharedSecret = cryptoOperations.executeDiffieHellmanKeyAgreement(
                (ECPrivateKey) ourTempEcdhKeyPair.getPrivate(), deviceEcdhPublicKeyBytes, getNode().getNodeId());

        // @formatter:off
        /*
         * 3.6.4.7.1 CKDF-TempExtract
         * The CKDF-TempExtract function is used to extract the key entropy from the non-uniformly distributed ECDH Shared Secret.
         *
         * CKDF-TempExtract(ConstantPRK, ECDH Shared Secret, KeyPub_A, KeyPub_B ) -> PRK
         *
         *  The function’s input is defined by:
         *      o ConstantPRK = 0x33 repeated 16 times
         *      o ECDH Shared Secret is the output of the ECDH key exchange
         *      o Public Keys of Nodes A and B
         *      o PRK = CMAC(ConstantPRK, ECDH Shared Secret | KeyPub_A | KeyPub_B )
         */
        // @formatter:on
        SecretKey tempExtractKey = cryptoOperations.buildAESKey(CKDF_TEMP_EXTRACT_CONSTANT);
        byte[] prkBytes = cryptoOperations.performAesCmac(tempExtractKey, ecdhSharedSecret,
                ourTempEcdhKeyPair.getPublic().getEncoded(), deviceEcdhPublicKeyBytes);

        // @formatter:off
        /*
         * 3.6.4.7.2 CKDF-TempExpand
         * CC:009F.01.00.11.08D 3.6.4.7.2 Once the PRK has been computed, the temporary Authentication, Encryption and
         * Nonce Keys MUST be derived using the CKDF-TempExpand function [23].
         *
         * CKDF-TempExpand(PRK, ConstantTE) -> {TempKeyCCM, TempPersonalizationString}
         *
         * The function’s input is defined by:
         *      o PRK is calculated in the previous section 3.6.4.7.1
         *      o ConstantTE = 0x88 repeated 15 times
         *
         * Calculations are performed as follows:
         *      o T1 = CMAC(PRK, ConstantTE | 0x01)
         *      o T2 = CMAC(PRK, T1 | ConstantTE | 0x02)
         *      o T3 = CMAC(PRK, T2 | ConstantTE | 0x03)
         *
         * Output is defined as follows:
         *      o TempKeyCCM = T1. Temporary CCM Key, combined Encryption and Authentication Key.
         *      o TempPersonalizationString = T2 | T3 Sigma
         */
        // @formatter:on
        SecretKey prkKey = cryptoOperations.buildAESKey(prkBytes);
        byte[] constantTePlusCounter = new byte[16];
        Arrays.fill(constantTePlusCounter, (byte) (0x88 & 0xFF));
        // Compute T1
        constantTePlusCounter[15] = 0x01;
        byte[] T1Bytes = cryptoOperations.performAesCmac(prkKey, constantTePlusCounter);
        this.tempAesCcmKey = cryptoOperations.buildAESKey(T1Bytes);
        // Compute T2
        constantTePlusCounter[15] = 0x02;
        byte[] T2Bytes = cryptoOperations.performAesCmac(prkKey, constantTePlusCounter);
        // Compute T3
        constantTePlusCounter[15] = 0x03;
        byte[] T3Bytes = cryptoOperations.performAesCmac(prkKey, constantTePlusCounter);
        byte[] stringBytes = new byte[T2Bytes.length + T3Bytes.length];
        for (int i = 0; i < T2Bytes.length; i++) {
            stringBytes[i] = T2Bytes[i];
        }
        int T2Length = T2Bytes.length;
        for (int i = 0; i < T3Bytes.length; i++) {
            stringBytes[i + T2Length] = (byte) (T3Bytes[i] & 0xFF);
        }
        this.tempPersonalizationString = stringBytes;
    }

    /**
     * TODO
     */
    @ZWaveResponseHandler(id = CommandClassSecurity2V1.SECURITY_2_COMMANDS_NONCE_GET, name = "SECURITY_2_COMMANDS_NONCE_GET")
    public void handleNonceGet(ZWaveCommandClassPayload payload, int endpoint) {
        Map<String, Object> response = CommandClassSecurity2V1.handleNonceGet(payload.getPayloadBuffer());
        int counterFromMessage = (int) response.get("SEQUENCE_NUMBER");
        if (!validateCounter(counterFromMessage)) {
            // Counter was identical to one which was recently received, ignore it
            return;
        }
        lastNonceGetReceived = System.currentTimeMillis();
        synchronized (lastNonceGetReceived) {
            lastNonceGetReceived.notify();
        }
        boolean mpanOutOfSync = false;
        boolean spanOutOfSync = true; // TODO: true until when, move to field?
        if (lastReceiverEntropyInputNoneSentToNode != null) {
            logger.warn("Overwriting old nonce data {}", Arrays.toString(lastReceiverEntropyInputNoneSentToNode));
        }
        lastReceiverEntropyInputNoneSentToNode = new byte[ENTROPHY_INPUT_SIZE];
        cryptoOperations.fillFromPrng(lastReceiverEntropyInputNoneSentToNode);

        // CC:009F.01.01.11.004 A sending node MUST specify a unique sequence number starting from a random value. Each
        // message MUST carry an increment of the value carried in the previous outgoing message.
        if (outgoingSequenceCounter == null) {
            outgoingSequenceCounter = new AtomicInteger(INSECURE_RANDOM.nextInt(100 - 1) + 1);
        }

        // Reply with the Nonce Report
        try {
            getController().enqueueNonce(new ZWaveCommandClassTransactionPayloadBuilder(getNode().getNodeId(),
                    CommandClassSecurity2V1.buildNonceReport(getAndIncrementOutboundSequenceNumber(), mpanOutOfSync,
                            spanOutOfSync, lastReceiverEntropyInputNoneSentToNode))
                                    .withPriority(TransactionPriority.NonceResponse).build());
            lastNonceGetReceived = System.currentTimeMillis();
            synchronized (lastResponseQueuedAt) {
                lastResponseQueuedAt.notify();
            }
        } catch (IOException e) {
            logger.error("NODE {}: error building SECURITY_2_COMMANDS_NONCE_REPORT", getNode().getNodeId(), e);
        }
    }

    /**
     * TODO
     */
    @ZWaveResponseHandler(id = CommandClassSecurity2V1.KEX_GET, name = "SECURITY_2_NETWORK_KEY_GET")
    public void handleKeyGet(ZWaveCommandClassPayload payload, int endpoint) {
        Map<String, Object> response = CommandClassSecurity2V1.handleSecurity2KexGet(payload.getPayloadBuffer());
        // Requested keys
        List<ZWaveS2KeyType> requestedKeyTypeList = (List<ZWaveS2KeyType>) response.get("REQUESTED_KEYS");
        // CC:009F.01.09.11.007 This field is used to request a network key. Only one key MUST be requested at a
        // time, i.e. only 1 bit MUST be set to ‘1’. This field MUST be encoded according to Table 19
        if (requestedKeyTypeList.size() != 1) {
            logger.error("NODE {}: KEY_GET wrong number of keys requested: {}", getNode().getNodeId(),
                    requestedKeyTypeList.size());
            return;
        }
        ZWaveS2KeyType keyType = requestedKeyTypeList.get(0);
        // TODO: ensure the key they requested matches one we granted

        // Reply with NETWORK_KEY_REPORT
        byte[] keyBytes = null; // TODO:
        if (keyBytes.length != 16) {
            logger.error("NODE {}: network key {} is wrong size: {}", getNode().getNodeId(), keyType, keyBytes.length);
            return;
        }
        // Don't use withExpectedResponseCommand because the response can vary
        getController().enqueue(new ZWaveCommandClassTransactionPayloadBuilder(getNode().getNodeId(),
                CommandClassSecurity2V1.buildNetworkKeyReport(keyType, keyBytes))
                        .withPriority(TransactionPriority.Immediate).build());
    }

    /**
     *
     * @param counterFromMessage
     * @return true if valid, false if a message with this counter was already received
     */
    private boolean validateCounter(Integer counterFromMessage) {
        logger.debug("NODE {}: received message with counter={} duplicateSequenceCounterQueue={}",
                getNode().getNodeId(), counterFromMessage, duplicateSequenceCounterQueue);
        if (duplicateSequenceCounterQueue.contains(counterFromMessage)) {
            logger.warn("NODE {}: dropping duplicate message with counter {}", getNode().getNodeId());
            return false;
        } else {
            duplicateSequenceCounterQueue.add(counterFromMessage);
            return true;
        }
    }

    /**
     * 3.6.4.1 ECDH Key pair generation
     * <p/>
     * Each S2 node has an ECDH key pair used to setup a temporary secure channel for the Network Key exchange. Key pair
     * generation is described in [28].
     */
    public void generateS2TempExchangeKeyInBackground() throws ZWaveCryptoException {
        if (ourTempEcdhKeyPairGenerationInProgress.get()) {
            logger.debug("NODE {}: SECURITY_2_INC ECDH generation already started, ignoring");
            return;
        }
        BACKGROUND_EXECUTOR_SERVICE.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    synchronized (ourTempEcdhKeyPairGenerationInProgress) {
                        ZWaveSecurity2CommandClass.this.ourTempEcdhKeyPair = cryptoOperations.generateECDHKeyPair();
                    }
                } catch (ZWaveCryptoException e) {
                    logger.error("NODE {}: SECURITY_2_INC State=FAILED, Reason=ECDH_TEMP_GEN_FAIL {}",
                            getNode().getNodeId(), e.getMessage(), e);
                    ZWaveSecurity2CommandClass.this.continueSecurePairing.set(false);
                }
            }
        });
    }

    /**
     * @return a copy of the bytes of the public key
     */
    public byte[] waitForS2TempKeyToFinishGenerating() {
        synchronized (ourTempEcdhKeyPairGenerationInProgress) {
            while (ZWaveSecurity2CommandClass.this.ourTempEcdhKeyPair == null) {
                try {
                    ourTempEcdhKeyPairGenerationInProgress.wait();
                } catch (InterruptedException e) {
                    // Per Java Concurrency In Practice, by Brian Gotez
                    Thread.currentThread().interrupt();
                }
            }
        }
        byte[] publicKeyBytes = this.ourTempEcdhKeyPair.getPublic().getEncoded();
        // Create a defensive copy as the caller may modify the public key byte arry
        byte[] toReturn = new byte[publicKeyBytes.length];
        System.arraycopy(publicKeyBytes, 0, toReturn, 0, publicKeyBytes.length);
        return toReturn;
    }

    /**
     * Waits up to 10 seconds for the a NONCE_GET command to be received from the node
     *
     * @return true if NONCE_GET was received, false if not
     * @deprecated use {@link #waitForResponseToQueue(int)}
     */
    // TODO: not used, delete
    @Deprecated
    public boolean waitForNonceGet() {
        boolean receivedNonceGetRecently = (System.currentTimeMillis() - lastNonceGetReceived) < TEN_SECONDS_MILLIS;
        if (!receivedNonceGetRecently) {
            try {
                synchronized (lastNonceGetReceived) {
                    lastNonceGetReceived.wait(TEN_SECONDS_MILLIS);
                }
            } catch (InterruptedException e) {
                // Per Java Concurrency In Practice, by Brian Gotez
                Thread.currentThread().interrupt();
            }
        }
        receivedNonceGetRecently = (System.currentTimeMillis() - lastNonceGetReceived) < TEN_SECONDS_MILLIS;
        logger.debug("Returning receivedNonceGetRecently={}", receivedNonceGetRecently);
        return receivedNonceGetRecently;
    }

    public boolean waitForResponseToQueue(int expectedCommandClassSecurity2V1) {
        boolean needToWait = (System.currentTimeMillis() - lastResponseQueuedAt) > TEN_SECONDS_MILLIS
                || lastResponseQueuedCommandClass != expectedCommandClassSecurity2V1;

        if (needToWait) {
            try {
                synchronized (lastResponseQueuedAt) {
                    lastResponseQueuedAt.wait(TEN_SECONDS_MILLIS);
                }
            } catch (InterruptedException e) {
                // Per Java Concurrency In Practice, Brian Gotez
                Thread.currentThread().interrupt();
            }
        }
        boolean wasResponseQueued = (System.currentTimeMillis() - lastResponseQueuedAt) < TEN_SECONDS_MILLIS
                && lastResponseQueuedCommandClass == expectedCommandClassSecurity2V1;
        logger.debug("Returning wasResponseQueued={} for {}", wasResponseQueued,
                SerialMessage.b2hex((byte) expectedCommandClassSecurity2V1));
        return wasResponseQueued;
    }

    /**
     * TODO
     *
     * @param senderEntrophyInput
     * @param receiverEntrophyInput
     * @return Mixed En
     * @throws ZWaveCryptoException
     */
    private SecureRandom instantiateSpan(byte[] senderEntrophyInput, byte[] receiverEntrophyInput)
            throws ZWaveCryptoException {
        // 3.6.4.9.1 SPAN Instantiation
        // Mix the 32 bytes EI into MEI, using CKDF-MEI-Extract and CKDF-MEI-Expand functions
        // CC:009F.01.00.11.00F The CTR_DRBG MUST be instantiated using the following profile

        // @formatter:off
        /*
         * 3.6.4.9.1.1.1 CKDF-MEI-Extract
         * CKDF-MEI-Extract(ConstNonce, SenderEI | ReceiverEI) -> NoncePRK
         *  The Input is defined by:
         *      o ConstNonce = 0x26 repeated 16 times
         *  The Output is obtained by:
         *      o NoncePRK = CMAC(ConstNonce, SenderEI | ReceiverEI)
         */
        // @formatter:on
        SecretKey constNonceKey = cryptoOperations.buildAESKey(CONST_NONCE_CONSTANT);
        byte[] noncePrk = cryptoOperations.performAesCmac(constNonceKey, senderEntrophyInput, receiverEntrophyInput);

        // @formatter:off
        /*
         * 3.6.4.9.1.1.2 CKDF-MEI-Expand
         * CKDF-MEI-Expand(NoncePRK, ConstEntropyInput) -> MEI
         *  The Input is defined by:
         *      o NoncePRK is the pseudo random value obtained in the Extract step.
         *      o ConstEntropyInput = 0x88 repeated 15 times
         *  The Output is obtained by:
         *      o T0 = ConstEntropyInput | 0x00
         *      o T1 = CMAC(NoncePRK, T0 | ConstEntropyInput | 0x01)
         *      o T2 = CMAC(NoncePRK, T1 | ConstEntropyInput | 0x02)
         *      o MEI = T1 | T2
         */
        // @formatter:om
        SecretKey noncePrkKey = cryptoOperations.buildAESKey(noncePrk);
        int constLength = CONST_ENTROPHY_INPUT_CONSTANT.length;
        byte[] T0 = new byte[constLength + 1];
        System.arraycopy(CONST_ENTROPHY_INPUT_CONSTANT, 0, T0, 0, constLength);
        T0[constLength] = 0x00;
        byte[] T1 = cryptoOperations.performAesCmac(noncePrkKey, T0, CONST_ENTROPHY_INPUT_CONSTANT, new byte[] {0x01});
        byte[] T2 = cryptoOperations.performAesCmac(noncePrkKey, T1, CONST_ENTROPHY_INPUT_CONSTANT, new byte[] {0x02});
        byte[] MEI = new byte[T1.length + T2.length];
        System.arraycopy(T1, 0, MEI, 0, T1.length);
        System.arraycopy(T2, 0, MEI, T1.length, T2.length);
        if(true) {
            throw new UnsupportedOperationException("CTR_DBRG not yet implemented due to java 9 needed and nonce questions"); // TODO:
        }
        return null;
    }

    /**
     * 3.6.4.4.2 Generate the Additional Authenticated Data (AAD) for AES CCM encryption and decryption
     *
     * @param destinationTag The use of this field depends on the actual frame. CC:009F.01.00.11.00A
     *                           If the field is used for a Singlecast frame, this field MUST carry the Receiver NodeID.
     *                           If the field is used for an S2 Multicast frame, this field MUST carry the S2 Multicast
     *                           Group ID.
     * @param messageLength  The total length in bytes of the Security 2 Message Encapsulation Command
     * @param extensionData  CC:009F.01.00.11.00B This field MUST contain all non-encrypted extension objects.
     *                           CC:009F.01.00.11.00C This field MUST include the Length and Type fields prepending the
     *                           actual data of each extension
     *
     * @return the AAD data
     * @throws IOException
     */
    private byte[] generateCcmAadData(int senderNodeId, int destinationTag, short messageLength, int sequenceNumber,
            boolean hasExtension, boolean hasEncryptedExtension, byte[] extensionData) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(30);
        // CC:009F.01.00.11.009 The following data structure MUST be used as AAD input for each CCM operation.
        baos.write(senderNodeId);
        baos.write(destinationTag);
        baos.write(homeId);
        baos.write(ByteBuffer.allocate(2).putShort(messageLength).array());
        baos.write(sequenceNumber);
        BitSet bitmask = new BitSet(8); // All zeros/unset, reserved are high 6 bits
        bitmask.set(0, hasExtension);
        bitmask.set(1, hasEncryptedExtension);
        CommandClassSecurity2V1.writeBitmask(bitmask, baos);
        baos.write(extensionData);
        return baos.toByteArray();
    }

    public boolean shouldEncapsulate(byte[] payloadBuffer) {
        boolean result = (payloadBuffer[1] & 0xff) == CommandClassSecurity2V1.SECURITY_2_COMMANDS_NONCE_GET
                || (payloadBuffer[1] & 0xff) == CommandClassSecurity2V1.SECURITY_2_COMMANDS_NONCE_REPORT;
        // TODO: log remove log entry
        logger.debug("S2 shouldEncapsulate for {} returning={}", SerialMessage.bb2hex(payloadBuffer), result);
        return result;
    }

    private byte getAndIncrementOutboundSequenceNumber() {
        return (byte) outgoingSequenceCounter.getAndIncrement();
    }

    /**
     * The node will request one or more security keys from us.  But, per the spec,  we are free to issue only a subset if we so choose.
     * We will only issue a single key to each node (see class javadoc for details).
     *
     * CC:009F.01.06.11.013 The value of this field MUST be the same set or a subset of the Requested Keys field advertised in the KEX Report by the joining node during initial S2 bootstrapping
     * @param requestedKeysList the list of keys which the node has requested
     * @return
     */
    public List<ZWaveS2KeyType> buildKeysToSendList(List<ZWaveS2KeyType> requestedKeysList) {
        // Find the strongest level requested and send only that key
        // TODO: future - send multiple keys
        ZWaveS2KeyType keyToSend = requestedKeysList.stream().sorted(Comparator.comparingInt(ZWaveS2KeyType::getSecurityLevel).reversed()).findFirst().get();
        logger.debug("NODE: {} will send key {} out of original list {}", getNode().getNodeId(), keyToSend, requestedKeysList);
        this.grantedKeysList = Collections.singletonList(keyToSend);
        this.keysThatNeedToBeSent = new ArrayList(this.grantedKeysList);
        // return defensive copy
        return new ArrayList(this.grantedKeysList );
    }

    @Override
    public byte[] securelyEncapsulateTransaction(byte[] payload) {
        logger.debug("Creating command message SECURITY_2_MESSAGE_ENCAPSULATION version 1");

        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        outputData.write(COMMAND_CLASS_KEY);
        outputData.write(SECURITY_2_MESSAGE_ENCAPSULATION);

        Map<ZWaveS2EncapsulationExtensionType, byte[]> extensionToDataTable = Collections.EMPTY_MAP; // TODO: where is this set?
        List<ZWaveS2EncapsulationExtensionType> unencryptedExtensionList = extensionToDataTable.keySet().stream().filter(t -> !t.isEncrypted()).collect(Collectors.toList());
        List<ZWaveS2EncapsulationExtensionType> encryptedExtensionList = extensionToDataTable.keySet().stream().filter(t -> t.isEncrypted()).collect(Collectors.toList());
        boolean hasUnencryptedExtension = !unencryptedExtensionList.isEmpty();
        boolean hasEncryptedExtension = !encryptedExtensionList.isEmpty();

        // Sequence Number (1 byte)
        int sequenceNumber = getAndIncrementOutboundSequenceNumber();
        outputData.write(sequenceNumber);

        // 8 bits: Extension / Encrypted Extension / Reserved
        BitSet bitmask = new BitSet(8); // All zeros/unset
        if (hasUnencryptedExtension) {
            bitmask.set(0);
        }
        if (hasEncryptedExtension) {
            bitmask.set(1);
        }
        writeBitmask(bitmask, outputData);

        try {
            byte[] unencryptedExtensionBuffer = buildExtensionBuffer(unencryptedExtensionList, extensionToDataTable);
            outputData.write(unencryptedExtensionBuffer);
            // Build data to encrypt
            ByteArrayOutputStream dataToEncrypt = new ByteArrayOutputStream();
            dataToEncrypt.write(buildExtensionBuffer(encryptedExtensionList, extensionToDataTable));
            dataToEncrypt.write(payload);

            byte[] nonce = new byte[ENTROPHY_INPUT_SIZE];
            inboundSpan.nextBytes(nonce);

            /*
             *  Build the AAD - note that unlike typical AEAD crypto structures, the AAD is NOT included in the structure for ZWave.  Instead, the AAD is computed by each side independently.  See 3.6.4.4 AES-128 CCM Encryption and Authentication
             */
            byte[] tempAad = generateCcmAadData(controllerNodeId, getNode().getNodeId(), (short) 0, sequenceNumber,
                    hasUnencryptedExtension, hasEncryptedExtension, unencryptedExtensionBuffer);
            // Before we can build the real AAD, we need to compute the message length, which requires the AAD
            int ciphertextLength = cryptoOperations.computeAesCcmOutputSize(dataToEncrypt.size(), nonce, tempAad);
            // Now that we have the size of the ciphertext, create the real aad with true message length
            int messageLength = outputData.size() + ciphertextLength;
            byte[] messageLengthBuffer = ByteBuffer.allocate(2).putShort((short) messageLength).array();
            byte[] aad = tempAad;
            System.arraycopy(messageLengthBuffer, 0, aad, 6, 2);

            // tempAesCcmKey will be null when permanent keys are in use
            if (tempAesCcmKey == null) {
                return cryptoOperations.encryptWithAesCcm(dataToEncrypt.toByteArray(), tempAesCcmKey, nonce, aad);
            } else {
                return cryptoOperations.decryptWithAesCcm(dataToEncrypt.toByteArray(), keyTypeAssigned, nonce, aad);
            }
        } catch (IOException |ZWaveCryptoException e) {
            // TODO: supposed to send new nonce get with reset or something?
            logger.error("NODE {}: S2 encapsulation failed", getNode().getNodeId(), e);
            // TODO: need fail message?
            return null;
        }
    }

    private byte[] buildExtensionBuffer(List<ZWaveS2EncapsulationExtensionType> extensionList,  Map<ZWaveS2EncapsulationExtensionType, byte[]> extensionToDataTable) throws IOException {
        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        for (int i = 0; i < extensionList.size(); i++) {
            ZWaveS2EncapsulationExtensionType extensionType = extensionList.get(i);
            byte[] bytes = extensionToDataTable.get(extensionType);
            int length = 2 + bytes.length; //  This field specifies the length of this extension, in bytes, including the “Extension Length” field
            outputData.write(length);
            // 8 bits: Extension type (6) / critical / more to follow
            BitSet bitmask = BitSet.valueOf(new byte[] {  extensionType.asByte() });
            bitmask.set(6, extensionType.isCritical());
            bitmask.set(7, (i+1) < extensionList.size());
            writeBitmask(bitmask, outputData);
            outputData.write(bytes);
        }
        return outputData.toByteArray();
    }

    @Override
    public byte[] decapsulateSecurityMessage(byte[] payloadBuffer) {
        // There are un-encrypted fields in the encapsulated message, parse those out first
        Map<String, Object> response = CommandClassSecurity2V1
                    .handleSecurity2DecapsulationUnencyptedPortions(payloadBuffer);
        boolean hasExtension = (boolean) response.get("HAS_EXTENSION");
        boolean hasEncryptedExtension = (boolean) response.get("HAS_ENCRYPTED_EXTENSION");
        int sequenceNumber = (int) response.get("SEQUENCE");
        // TODO: validate sequence
        byte[] senderEntrophyInput = (byte[]) response.get("SPAN_SENDER_ENTROPHY");
        /*
         *  CC:009F.01.00.11.00B  This field MUST contain all non-encrypted extension objects.
         * CC:009F.01.00.11.00C  This field MUST include the Length and Type fields prepending the actual data of each extension
         */
        byte[] nonEncryptedExtensionBytes = (byte[]) response.get("EXTENSION_BYTES");
        byte[] cipherBytes = (byte[]) response.get("ENCRYPTED_BYTES");

        byte[] aad =null;
        byte[] nonce = null;
        try {
            if (senderEntrophyInput != null) {
                // @formatter:off
                /*
                 * CC:009F.01.00.11.01F
                 * If a SPAN Extension is present, the Receiver MUST:
                 *      (continued below)
                 *      i. Instantiate a new SPAN Generator using the Receiver’s Entropy Input stored locally and the Sender’s Entropy Input just received.
                 *      ii. Store the inner SPAN state in a SPAN table entry with the Sender as Peer NodeID.
                 *      iii. Generate a SPAN by running the NextNonce function on the newly instantiated inner SPAN state.
                 *      iv. Attempt authentication with the SPAN.
                 *      v. If the authentication succeeds, skip to step 5.
                 *      vi. If the authentication fails, the Receiver MUST go to step 2
                 */
                // @formatter:on
                if (lastReceiverEntropyInputNoneSentToNode == null) {
                    logger.error(
                            "NODE {}: S2 decapsulation error, message dropped: node sent SEI but lastNonceGenerated is null",
                            getNode().getNodeId());
                    return null; // fail silently since this is not in Table 11, Security 2 bootstrapping
                }
                // i. Instantiate a new SPAN Generator using the Receiver’s Entropy Input stored locally and the
                // Sender’s Entropy Input just received.
                // ii. Store the inner SPAN state in a SPAN table entry with the Sender as Peer NodeID.
                inboundSpan = instantiateSpan(senderEntrophyInput, lastReceiverEntropyInputNoneSentToNode);
                lastReceiverEntropyInputNoneSentToNode = null; // Clear out lastNoneGenerated since we used the data to
                                                               // build the SPAN
            }
            // Decrypt the ciphertext using AES CCM
            int destinationTag = controllerNodeId; // Singlecast frame is all we support, so the Receiver NodeID which
                                                   // is that of the controller
            int messageLength = payloadBuffer.length;
            aad = generateCcmAadData(getNode().getNodeId(), destinationTag, (short) messageLength, sequenceNumber,
                    hasExtension, hasEncryptedExtension, nonEncryptedExtensionBytes);
            nonce = new byte[ENTROPHY_INPUT_SIZE];
            inboundSpan.nextBytes(nonce);
        } catch (ZWaveCryptoException | IOException e) {
            logger.error("NODE {}: S2 decapsulation error, message dropped: error generating nonce from inboundSpan",
                    getNode().getNodeId(), e);
            return null; // fail silently since this is not in Table 11, Security 2 bootstrapping
        }
        try {
            // tempAesCcmKey will be null when permanent keys are in use
            if (tempAesCcmKey == null) {
                return cryptoOperations.decryptWithAesCcm(cipherBytes, tempAesCcmKey, nonce, aad);
            } else {
                return cryptoOperations.decryptWithAesCcm(cipherBytes, keyTypeAssigned, nonce, aad);
            }
        } catch (ZWaveCryptoException e) {
            // TODO: supposed to send new nonce get with reset or something?
            logger.error("NODE {}: S2 decapsulation failed, dropping message", getNode().getNodeId(), e);
            sendFailMessage(ZWaveS2FailType.KEX_FAIL_DECRYPT);
            return null;
        }
    }

    public AtomicBoolean getContinueSecurePairing() {
        return continueSecurePairing;
    }

    public ZWaveProtocolViolationException getProtocolViolationException() {
        return protocolViolationException;
    }

    public ZwaveKexData getKexReportDataReceivedFromNode() {
        return kexReportDataFromNode;
    }

    public byte[] getDeviceEcdhPublicKeyBytes() {
        // Must return a reference to the real array (as opposed to a defensive copy) so the user can set the 1st two
        // bits in authenticated mode
        return deviceEcdhPublicKeyBytes;
    }
}
