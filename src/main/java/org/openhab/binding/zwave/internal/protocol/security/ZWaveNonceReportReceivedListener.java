package org.openhab.binding.zwave.internal.protocol.security;

public interface ZWaveNonceReportReceivedListener {
    public void nonceReportReceived(ZWaveNonceReportData reportData);
}
