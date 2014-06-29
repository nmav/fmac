CC=arm-linux-gcc
STRIP=arm-linux-strip
#CC=gcc
#STRIP=strip
CFLAGS=-O2

fmac: fmac.c
	$(CC) -c $(CFLAGS) fmac.c
	$(CC) -o fmac fmac.o -lcrypto
	$(STRIP) fmac

clean:
	rm -f fmac fmac.o

all: fmac

	