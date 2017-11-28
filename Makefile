all: import

import:
	mkdir src/lib
	git clone https://github.com/cnorick/Crypto-project1.git src/lib/aes
	git clone https://github.com/cnorick/Crypto-project2.git src/lib/rsa