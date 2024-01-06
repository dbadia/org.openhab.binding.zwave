package org.openhab.binding.zwave.internal.protocol.initialization;

import org.openhab.binding.zwave.internal.protocol.commandclass.ZWaveSecurity2CommandClass;

public class InitializationTestHelper {

    /**
     * Helper method so we can invoke {@link ZWaveNodeInitStageAdvancer#doSecureS2Stages(ZWaveSecurity2CommandClass)}
     * for junit testing without making the method public
     */
    public static void invokeDoSecureS2Stages(ZWaveNodeInitStageAdvancer advancer,
            ZWaveSecurity2CommandClass security2CommandClass) {
        advancer.doSecureS2Stages(security2CommandClass);
    }
}
