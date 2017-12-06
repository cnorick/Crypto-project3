#!/bin/bash

rm -rf test/
mkdir test
mkdir test/foo
sample1="Hello World"
sample2="It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way--in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."
echo $sample1 > test/sample1
echo $sample2 > test/sample2
cp test/sample1 test/sample2 test/foo

# Create CAs.
./rsa-keygen -p test/lsignerPub -s test/lsignerPriv -n 516
./rsa-keygen -p test/usignerPub -s test/usignerPriv -n 516

# Create locker cert.
./rsa-keygen -p test/lockerPub -s test/lockerPriv -n 516 -c test/lsignerPriv

# Create unlocker cert.
./rsa-keygen -p test/unlockerPub -s test/unlockerPriv -n 516 -c test/usignerPriv

./lock -d test/foo -p test/unlockerPub -r test/lockerPriv -vk test/usignerPub
./unlock -d test/foo -p test/lockerPub -r test/unlockerPriv -vk test/lsignerPub
if ! diff <(echo "$sample1") test/foo/sample1 >/dev/null
    then
        echo 'Unlocked files do not match original'
        exit 1
fi
if ! diff <(echo "$sample2") test/foo/sample2 >/dev/null
    then
        echo 'Unlocked files do not match original'
        exit 1
fi


# Test RSA sign/validate
./rsa-sign -k test/lockerPriv -m test/sample2 -s test/sample2Sig
./rsa-sign -k test/lockerPriv -m test/sample1 -s test/sample1Sig
output="$(./rsa-validate -k test/lockerPub -m test/sample2 -s test/sample2Sig)"
if [ "$output" == "False" ]
    then
        echo 'Unable to validate file'
        exit 1
fi
output="$(./rsa-validate -k test/lockerPub -m test/sample2 -s test/sample1Sig)"
if [ "$output" == "True" ]
    then
        echo 'Validated file that should not have been validated'
        exit 1
fi


# Test cbcmac
./cbcmac-tag -k test/lockerPriv -m test/sample2 -t test/sample2Tag
./cbcmac-tag -k test/lockerPriv -m test/sample1 -t test/sample1Tag

output="$(./cbcmac-validate -k test/lockerPub -m test/sample2 -t test/sample2Tag)"
if [ "$output" == "False" ]
    then
        echo 'Unable to validate file with tag'
        exit 1
fi
output="$(./cbcmac-validate -k test/lockerPub -m test/sample2 -t test/sample1Tag)"
if [ "$output" == "True" ]
    then
        echo 'Validated file with tag that should not have been validated'
        exit 1
fi

echo 'SUCCESS'