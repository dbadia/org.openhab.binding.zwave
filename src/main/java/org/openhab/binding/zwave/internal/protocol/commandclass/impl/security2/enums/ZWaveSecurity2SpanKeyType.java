package org.openhab.binding.zwave.internal.protocol.commandclass.impl.security2.enums;

/**
 * see 3.1.5.1.1 Table 2, SPAN table::Security key
 *
 */
public enum ZWaveSecurity2SpanKeyType {
    ECDH_TEMPORARY_KEY,
    S2_2,
    S2_1,
    S2_0,
    S0;
}