aesRepo := https://github.com/cnorick/Crypto-project1.git
aesDir := src/lib/aes
rsaRepo := https://github.com/cnorick/Crypto-project2.git
rsaDir := src/lib/rsa

all: install_lib

import:
	mkdir -p src/lib
	if [ ! -d "$(rsaDir)" ]; then git clone $(rsaRepo) $(rsaDir); fi
	if [ ! -d "$(aesDir)" ]; then git clone $(aesRepo) $(aesDir); fi
	
install_lib: import
	$(MAKE) -C $(rsaDir)
	$(MAKE) -C $(aesDir)

clean:
	rm -fr src/lib