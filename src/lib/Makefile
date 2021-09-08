name=libkeystore.so

dir_blowfish=../crypt_blowfish-1.3

obj=$(dir_blowfish)/crypt_blowfish.o \
	$(dir_blowfish)/crypt_gensalt.o \
	$(dir_blowfish)/wrapper.o \
	crypt.o \
	error_internal.o \
	fs.o \
	io.o \
	keystore.o

cc=gcc
cflags=-fPIC -Wall -D_GNU_SOURCE -g
ldflags=-shared

all: $(name)

$(name): $(obj)
	$(cc) -o $@ $^ $(ldflags)

%.o: %.c
	$(cc) -o $@ -c $< $(cflags)

install: $(name)
	mkdir -p /usr/local/include/keystore
	cp -f keystore.h /usr/local/include/keystore
	cp -f error.h /usr/local/include/keystore
	cp -f libkeystore.so /usr/local/lib

clean:
	rm -f $(obj) $(name)
