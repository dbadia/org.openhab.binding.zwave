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
public enum ZWaveS2KeyType implements ZWaveS2BitmaskEnumType {
    S2_ACCESS_CONTROL(2, "S2 Access Control Class", 1, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY_S2_2, true, true),
    S2_AUTHENTICATED(1, "S2 Authenticated Class S2", 2, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY_S2_1, true,
            false),
    S2_UNAUTHENTICATED(3, "S2 Unauthenticated Class", 3, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY_S2_0, false,
            false),
    S0(7, "S0 Secure legacy devices", 4, ZWaveBindingConstants.CONFIGURATION_NETWORKKEY, false, false);

    private static List<ZWaveS2KeyType> keyTypesFromWeakestToStrongestCache = null;
    private String toStringString;
    private int bitPosition;
    /**
     * CC:009F.01.05.11.015
     * Table 19, Requested Keys
     * 1 - highest, 4 = lowest
     */
    private int securityLevel;
    /**
     * The name of the this key as used in {@link ZWaveControllerHandler} and defined in {@link ZWaveBindingConstants}
     */
    private String controllerConstantName;
    private boolean requiresDskConfirmation;
    private boolean requiredToSupportCsaWhenRequestedByNode;

    private ZWaveS2KeyType(int bitPosition, String description, int securityLevel, String controllerConstantName,
            boolean requiresDskConfirmation, boolean requiredToSupportCsaIfRequestedByNode) {
        this.bitPosition = bitPosition;
        this.toStringString = description + " " + super.toString();
        this.securityLevel = securityLevel;
        this.controllerConstantName = controllerConstantName;
        this.requiresDskConfirmation = requiresDskConfirmation;
        this.requiredToSupportCsaWhenRequestedByNode = requiredToSupportCsaIfRequestedByNode;
    }

    public static List<ZWaveS2KeyType> getKeyTypesFromWeakestToStrongest(boolean excludeS0) {
        if (keyTypesFromWeakestToStrongestCache == null) {
            keyTypesFromWeakestToStrongestCache = Arrays.asList(ZWaveS2KeyType.values());
            keyTypesFromWeakestToStrongestCache.sort(new Comparator<ZWaveS2KeyType>() {

                @Override
                public int compare(ZWaveS2KeyType first, ZWaveS2KeyType second) {
                    return second.securityLevel - first.securityLevel;
                }
            });
            keyTypesFromWeakestToStrongestCache = Collections.unmodifiableList(keyTypesFromWeakestToStrongestCache);
        }
        List<ZWaveS2KeyType> copy = new ArrayList<>(keyTypesFromWeakestToStrongestCache);
        if (excludeS0) {
            copy.remove(ZWaveS2KeyType.S0);
        }
        return copy;
    }

    // TODO: delete?
    public static ZWaveS2KeyType mapFromControllerString(String controllerConstantName) {
        // This is only called a few times during init, don't bother caching
        for (ZWaveS2KeyType keyType : ZWaveS2KeyType.values()) {
            if (keyType.controllerConstantName.equals(controllerConstantName)) {
                return keyType;
            }
        }
        return null;
    }

    // TODO: delete
    public static void main(String[] args) {
        try {
            byte[] bytes = ByteBuffer.allocate(2).putShort((short) 5).array();
            System.out.println(SerialMessage.bb2hex(bytes));
            System.out.println(getKeyTypesFromWeakestToStrongest(false));
            System.out.println(getKeyTypesFromWeakestToStrongest(true));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean isRequiresDskConfirmation() {
        return requiresDskConfirmation;
    }

    @Override
    public int getBitPosition() {
        return bitPosition;
    }

    @Override
    public String toString() {
        return toStringString;
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

}