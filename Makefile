aesRepo := https://github.com/cnorick/Crypto-project1.git
aesDir := src/lib/aes
rsaRepo := https://github.com/cnorick/Crypto-project2.git
rsaDir := src/lib/rsa

all: install_lib move_scripts

import:
	# mkdir -p src/lib
	# if [ ! -d "$(rsaDir)" ]; then git clone $(rsaRepo) $(rsaDir); fi
	# if [ ! -d "$(aesDir)" ]; then git clone $(aesRepo) $(aesDir); fi
	
install_lib: import
	# $(MAKE) -C $(rsaDir)
	# $(MAKE) -C $(aesDir)

move_scripts:
	cp bash_scripts/rsa-sign.sh rsa-sign
	chmod a+x rsa-sign
	cp bash_scripts/rsa-validate.sh rsa-validate
	chmod a+x rsa-validate
	cp bash_scripts/cbcmac-validate.sh cbcmac-validate
	chmod a+x cbcmac-validate
	cp bash_scripts/cbcmac-tag.sh cbcmac-tag
	chmod a+x cbcmac-tag
	cp bash_scripts/rsa-keygen.sh rsa-keygen
	chmod a+x rsa-keygen
	cp bash_scripts/lock.sh lock
	chmod a+x lock
	cp bash_scripts/unlock.sh unlock
	chmod a+x unlock

clean:
	rm -fr src/lib