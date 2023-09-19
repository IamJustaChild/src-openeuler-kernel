#!/bin/bash

# from: https://repo.openeuler.org/${openEuler_version}/source/RPM-GPG-KEY-openEuler
# sha256: 006e79d37c10e74c24df6d07c4efc4176515cec009daa5ed493b06f5b6ef39c1
CERT="RPM-GPG-KEY-openEuler-compass-ci"
# process result for kernel building
CERT_OUT="pubring.gpg"

# base64 decode with removing prefix and suffix
for cert in $CERT; do
	cat $cert | head -n -2 | tail -n +2 | base64 -d > $cert.gpg
done

# Now EBS use subkey to sign, but kernel can only parse main key. So we need to
# extract subkey information and wrap to a main key format.

# The PGP data can be parsered with https://cirw.in/gpg-decoder/

# Extra User ID Packet
# start: 400; length: 38
dd if=$CERT.gpg of=$CERT.userid.gpg skip=400 bs=1c count=38
# Extra Public-Subkey Packet
# start: 902 + 1(wrap cipherTypeByte); length: 400 - 1
# cipherTypeByte: 0x99 = 10 0110(wrap to a main key) 01
echo -en "\x99" > $CERT.subkey.gpg
dd if=$CERT.gpg of=$CERT.subkey.gpg skip=903 bs=1c count=399 seek=1

# merge all cert information
cat $CERT.subkey.gpg $CERT.userid.gpg > $CERT_OUT
# cleanup
rm -f RPM-GPG-KEY-openEuler-*
