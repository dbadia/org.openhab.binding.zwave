package org.openhab.binding.zwave.internal.protocol.security.enums;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.openhab.binding.zwave.ZWaveBindingConstants;
import org.openhab.binding.zwave.handler.ZWaveControllerHandler;
import org.openhab.binding.zwave.internal.protocol.SerialMessage;

/**
 * from CC:009F.01.05.11.015
 *
 */
public enum ZWaveKeyType implements ZWaveS2BitmaskEnumType {
    S2_TEMP(-1, "S2 Temporary Pairing", 100, "invalid", false, false),
    S2_ACCESS_CONTROL(2, "S2 Access Control Class", 1, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY_S2_2, true, true),
    S2_AUTHENTICATED(1, "S2 Authenticated Class S2", 2, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY_S2_1, false,
            true),
    S2_UNAUTHENTICATED(0, "S2 Unauthenticated Class", 3, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY_S2_0, false,
            false),
    S0(7, "S0 Secure legacy devices", 4, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY, false, false);

    private static List<ZWaveKeyType> keyTypesFromWeakestToStrongestCache = null;
    private int bitPosition;
    /**
     * CC:009F.01.05.11.015
     * Table 19, Requested Keys
     * 1 - most secure, 4 = least secure
     */
    private int securityLevel;
    /**
     * The name of the this key as used in {@link ZWaveControllerHandler} and defined in {@link ZWaveBindingConstants}
     */
    private String controllerConstantName;
    private boolean requiredToSupportCsaWhenRequestedByNode;
    /**
     * Device authentication, where the user must input or scan a code on the device being included
     * See CC:009F.01.08.11.007, CC:009F.01.08.11.008, CC:009F.01.08.11.00B
     */
    private boolean authenticated;

    private ZWaveKeyType(int bitPosition, String description, int securityLevel, String controllerConstantName,
            boolean requiredToSupportCsaIfRequestedByNode, boolean authenticated) {
        this.bitPosition = bitPosition;
        this.securityLevel = securityLevel;
        this.controllerConstantName = controllerConstantName;
        this.requiredToSupportCsaWhenRequestedByNode = requiredToSupportCsaIfRequestedByNode;
        this.authenticated = authenticated;
    }

    public static List<ZWaveKeyType> valuesWeakestToStrongest(boolean excludeS0) {
        if (keyTypesFromWeakestToStrongestCache == null) {
            keyTypesFromWeakestToStrongestCache = Arrays.asList(ZWaveKeyType.values());
            keyTypesFromWeakestToStrongestCache.sort(new Comparator<ZWaveKeyType>() {

                @Override
                public int compare(ZWaveKeyType first, ZWaveKeyType second) {
                    return second.securityLevel - first.securityLevel;
                }
            });
            keyTypesFromWeakestToStrongestCache = Collections.unmodifiableList(keyTypesFromWeakestToStrongestCache);
        }
        List<ZWaveKeyType> copy = new ArrayList<>(keyTypesFromWeakestToStrongestCache);
        if (excludeS0) {
            copy.remove(ZWaveKeyType.S0);
        }
        // Always exclude the temp key
        copy.remove(ZWaveKeyType.S2_TEMP);
        return copy;
    }

    // TODO: delete
    public static void main(String[] args) {
        try {
            byte[] bytes = ByteBuffer.allocate(2).putShort((short) 5).array();
            System.out.println(SerialMessage.bb2hex(bytes));
            System.out.println(valuesWeakestToStrongest(false));
            System.out.println(valuesWeakestToStrongest(true));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public int getBitPosition() {
        return bitPosition;
    }

    public boolean isRequiredToSupportCsaWhenRequestedByNode() {
        return requiredToSupportCsaWhenRequestedByNode;
    }

    /**
     * Lower is more secure
     */
    public int getSecurityLevel() {
        return securityLevel;
    }

    public String getControllerConstantName() {
        return controllerConstantName;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}