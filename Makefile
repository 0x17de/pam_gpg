all: lib test

clean:
	rm -rf pam_gpg.so pam_gpg

lib:
	gcc -std=c99 -Wall -pedantic main.c -shared -fPIC -o pam_gpg.so

test:
	gcc -std=c99 -Wall -pedantic -DLIBTEST main.c -g -o pam_gpg
