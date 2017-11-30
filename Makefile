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

clean:
	rm -fr src/lib