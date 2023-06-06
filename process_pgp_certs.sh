#!/bin/bash

# from: https://repo.openeuler.org/openEuler-22.03-LTS/source/RPM-GPG-KEY-openEuler
# sh256: b09bf8bf7dae9aa6b24b170b6b85dd1717e14e674f270d14da0436e8dfc4260e
CERT_2203="RPM-GPG-KEY-openEuler-22.03"
# from: https://repo.openeuler.org/openEuler-22.03-LTS-SP1/source/RPM-GPG-KEY-openEuler
# sha256: 006e79d37c10e74c24df6d07c4efc4176515cec009daa5ed493b06f5b6ef39c1
CERT_2203_SP1="RPM-GPG-KEY-openEuler-22.03-SP1"
# process result for kernel building
CERT_OUT="pubring.gpg"

# base64 decode with removing prefix and suffix
for cert in $CERT_2203 $CERT_2203_SP1; do
	cat $cert | head -n -2 | tail -n +2 | base64 -d > $cert.gpg
done

# 22.03 SP1 use subkey to sign, but kernel can only parse main key. So we need to
# extract subkey information and wrap to a main key format.

# The PGP data can be parsered with https://cirw.in/gpg-decoder/

# Extra User ID Packet
# start: 400; length: 38
dd if=$CERT_2203_SP1.gpg of=$CERT_2203_SP1.userid.gpg skip=400 bs=1c count=38
# Extra Public-Subkey Packet
# start: 902 + 1(wrap cipherTypeByte); length: 400 - 1
# cipherTypeByte: 0x99 = 10 0110(wrap to a main key) 01
echo -en "\x99" > $CERT_2203_SP1.subkey.gpg
dd if=$CERT_2203_SP1.gpg of=$CERT_2203_SP1.subkey.gpg skip=903 bs=1c count=399 seek=1

# 22.03 use main key to sign, so we dont need to deal it.

# merge all cert information
cat $CERT_2203_SP1.subkey.gpg $CERT_2203_SP1.userid.gpg $CERT_2203.gpg > $CERT_OUT
# cleanup
rm -f RPM-GPG-KEY-openEuler-*
