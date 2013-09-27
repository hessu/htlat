
all: htlat

# change next line to no (lowercase) if you dont have OpenSSL
SSL=no

# change this to point to the compiled (or installed) OpenSSL tree

# OPENSSL=/usr/local/ssl
#OPENSSL=../openssl-0.9.5a

# OpenSSL can be removed by removing -DOpenSSL -flag from CFLAGS
# 

CC = gcc
LD = gcc

CFLAGS = -Wall -Wstrict-prototypes -g -D_REENTRANT 
#CFLAGS = ${SSL} -Wall -Wstrict-prototypes -g -D_REENTRANT
#LDFLAGS = -lpthread -lssl -lcrypto
LDFLAGS = -lpthread


#  -L/usr/local/ssl/lib -lssl  -lcrypto

# For Solaris:
#OSLDFLAGS = -lnsl -lsocket -lposix4

.c.o:
ifeq ($(SSL),no)
	$(CC) $(CFLAGS) $(OSCFLAGS) -c $<
else
	$(CC) -DOpenSSL $(CFLAGS) $(OSCFLAGS) -c $<
endif


clean:
	rm -f *.o *~ *.bak core
distclean: clean
	rm -f httime

LATBITS = htlat.o hmalloc.o
htlat: $(LATBITS)
ifeq ($(SSL),no)
	$(LD)  $(LATBITS) $(LDFLAGS) $(OSLDFLAGS) -o htlat
else
	$(LD)  $(LATBITS) $(LDFLAGS) -lssl -lcrypto $(OSLDFLAGS) -o htlat

endif

htlat.o:	htlat.c hmalloc.h
hmalloc.o:	hmalloc.c hmalloc.h
