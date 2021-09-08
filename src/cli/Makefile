name=keystore

obj=main.o sep.o

cc=gcc
cflags=-I/usr/local/include -Wall -D_GNU_SOURCE -g
ldflags=-L/usr/local/lib -lkeystore

all: $(name)

$(name): $(obj)
	$(cc) -o $@ $^ $(ldflags)

%.o: %.c
	$(cc) -o $@ -c $< $(cflags)

install:

clean:
	rm -f $(obj) $(name)
