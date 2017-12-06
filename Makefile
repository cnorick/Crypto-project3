all: move_scripts

move_scripts:
	cp bash_scripts/rsa-sign.sh rsa-sign
	cp bash_scripts/rsa-validate.sh rsa-validate
	cp bash_scripts/cbcmac-validate.sh cbcmac-validate
	cp bash_scripts/cbcmac-tag.sh cbcmac-tag
	cp bash_scripts/rsa-keygen.sh rsa-keygen
	cp bash_scripts/lock.sh lock
	cp bash_scripts/unlock.sh unlock

	chmod a+x unlock
	chmod a+x rsa-validate
	chmod a+x rsa-sign
	chmod a+x cbcmac-validate
	chmod a+x cbcmac-tag
	chmod a+x rsa-keygen
	chmod a+x lock

test: move_scripts
	cp bash_scripts/test.sh test_script
	chmod a+x test_script
	./test_script
	rm test_script

clean:
	rm -rf unlock rsa-validate rsa-sign cbcmac-validate cbcmac-tag rsa-keygen lock test