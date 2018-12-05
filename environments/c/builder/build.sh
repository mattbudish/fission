#!/bin/sh

set -eux

srcDir=/usr/src/$(basename ${SRC_PKG})

trap "rm -rf ${srcDir}" EXIT

if [ -d ${SRC_PKG} ]
then
    echo "Building in directory ${srcDir}"
    ln -sf ${SRC_PKG} ${srcDir}
    cd $(dirname ${DEPLOY_PKG})
    cmake -DCMAKE_BUILD_TYPE=Release ${srcDir} && make
elif [ -f ${SRC_PKG} ]
then
    echo "Building file ${SRC_PKG} in ${srcDir}"
    mkdir -p ${srcDir}
    cp ${SRC_PKG} ${srcDir}/function.c
    cd ${srcDir}
    clang -shared -fpic -o ${DEPLOY_PKG}/user -O2 function.c
fi
