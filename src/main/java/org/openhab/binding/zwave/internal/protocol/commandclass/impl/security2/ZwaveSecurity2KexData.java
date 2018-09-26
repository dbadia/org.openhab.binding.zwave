package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2;

import java.util.Collections;
import java.util.List;

import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2ECDHProfile;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2KexScheme;
import org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums.ZWaveSecurity2KeyType;

/**
 * Holder for KEX_SET and KEX_REPORT data.
 * Both sets of data are sent to the other node, then later confirmed once encryption is enabled
 * <p/>
 * Note that the echo bit is not in this object as it is to be excluded from the comparison
 *
 * @author Dave Badia
 *
 */
public class ZwaveSecurity2KexData {
    private boolean clientSideAuthentication;

    private List<ZWaveSecurity2KexScheme> kexSchemesList;
    private List<ZWaveSecurity2ECDHProfile> ecdhProfileList;
    private List<ZWaveSecurity2KeyType> keyTypeList;

    /**
     * KEX_REPORT friendly constructor - accepts a list of schemes and a list of ecdhprofiles
     */
    public ZwaveSecurity2KexData(boolean clientSideAuthentication, List<ZWaveSecurity2KexScheme> kexSchemesList,
            List<ZWaveSecurity2ECDHProfile> ecdhProfileList, List<ZWaveSecurity2KeyType> keyTypeList) {
        super();
        this.clientSideAuthentication = clientSideAuthentication;
        this.keyTypeList = keyTypeList;
        this.kexSchemesList = kexSchemesList;
        this.ecdhProfileList = ecdhProfileList;
    }

    /**
     * KEX_SET friendly constructor - accepts a single scheme and a single ecdhprofile
     */
    public ZwaveSecurity2KexData(boolean clientSideAuthentication, ZWaveSecurity2KexScheme kexScheme,
            ZWaveSecurity2ECDHProfile ecdhProfile, List<ZWaveSecurity2KeyType> keyTypeList) {
        this.clientSideAuthentication = clientSideAuthentication;
        this.keyTypeList = keyTypeList;
        this.kexSchemesList = Collections.singletonList(kexScheme);
        this.ecdhProfileList = Collections.singletonList(ecdhProfile);
    }

    public boolean isClientSideAuthentication() {
        return clientSideAuthentication;
    }

    public List<ZWaveSecurity2KexScheme> getKexSchemesList() {
        return kexSchemesList;
    }

    public List<ZWaveSecurity2ECDHProfile> getEcdhProfileList() {
        return ecdhProfileList;
    }

    public List<ZWaveSecurity2KeyType> getKeyTypeList() {
        return keyTypeList;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("ZwaveSecurity2KexData [clientSideAuthentication=");
        builder.append(clientSideAuthentication);
        builder.append(", kexSchemesList=");
        builder.append(kexSchemesList);
        builder.append(", ecdhProfileList=");
        builder.append(ecdhProfileList);
        builder.append(", keyTypeList=");
        builder.append(keyTypeList);
        builder.append("]");
        return builder.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((ecdhProfileList == null) ? 0 : ecdhProfileList.hashCode());
        result = prime * result + (clientSideAuthentication ? 1231 : 1237);
        result = prime * result + ((keyTypeList == null) ? 0 : keyTypeList.hashCode());
        result = prime * result + ((kexSchemesList == null) ? 0 : kexSchemesList.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ZwaveSecurity2KexData other = (ZwaveSecurity2KexData) obj;
        if (ecdhProfileList == null) {
            if (other.ecdhProfileList != null) {
                return false;
            }
        } else if (!ecdhProfileList.equals(other.ecdhProfileList)) {
            return false;
        }
        if (clientSideAuthentication != other.clientSideAuthentication) {
            return false;
        }
        if (keyTypeList == null) {
            if (other.keyTypeList != null) {
                return false;
            }
        } else if (!keyTypeList.equals(other.keyTypeList)) {
            return false;
        }
        if (kexSchemesList == null) {
            if (other.kexSchemesList != null) {
                return false;
            }
        } else if (!kexSchemesList.equals(other.kexSchemesList)) {
            return false;
        }
        return true;
    }

}
