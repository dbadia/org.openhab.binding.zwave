#!/bin/bash
set errexit # halt on non-zero exit code
set nounset # aborts if you try to expand an unset variable

pushd /d/code/eclipse/eclipse-openhab8/git/openhab-core/bundles/org.openhab.core.io.jetty.certificate/
./install.sh
popd