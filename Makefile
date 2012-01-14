CFLAGS=-O2 -Wall
all: eoip evlan
eoip: eoip.c
	$(CC) $(CFLAGS) -Wno-unused-result eoip.c -o eoip
evlan: evlan.c
	$(CC) $(CFLAGS) -Wno-unused-result evlan.c -o evlan
clean:
	rm -f eoip evlan
