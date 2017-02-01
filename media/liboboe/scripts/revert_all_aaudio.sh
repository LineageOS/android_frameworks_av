#!/bin/bash

echo "Revert Oboe names to AAudio names"

echo "Top is ${ANDROID_BUILD_TOP}"
LIBOBOE_DIR=${ANDROID_BUILD_TOP}/frameworks/av/media/liboboe
echo "LIBOBOE_DIR is ${LIBOBOE_DIR}"
OBOESERVICE_DIR=${ANDROID_BUILD_TOP}/frameworks/av/services/oboeservice
echo "OBOESERVICE_DIR is ${OBOESERVICE_DIR}"
OBOETEST_DIR=${ANDROID_BUILD_TOP}/cts/tests/tests/nativemedia/aaudio/src/
echo "OBOETEST_DIR is ${OBOETEST_DIR}"

git checkout -- ${LIBOBOE_DIR}/examples
git checkout -- ${LIBOBOE_DIR}/include
git checkout -- ${LIBOBOE_DIR}/src
git checkout -- ${LIBOBOE_DIR}/tests
git checkout -- ${LIBOBOE_DIR}/Android.bp
git checkout -- ${LIBOBOE_DIR}/README.md
git checkout -- ${LIBOBOE_DIR}/liboboe.map.txt
git checkout -- ${OBOESERVICE_DIR}
git checkout -- ${OBOETEST_DIR}

rm -rf ${LIBOBOE_DIR}/include/aaudio

find . -name "*aaudio*.cpp" -print -delete
find . -name "*AAudio*.cpp" -print -delete
find . -name "*AAudio*.h"   -print -delete
