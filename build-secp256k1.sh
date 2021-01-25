#!/bin/sh

set +e

cd c-secp256k1 
./autogen.sh
./configure --enable-experimental --enable-module-recovery --enable-endomorphism
make clean
sleep 0.1
make clean
rm -rf .libs src/.libs
# make
cd ..