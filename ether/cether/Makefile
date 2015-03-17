##############################################################################
##
##############################################################################

BASE_DIR=.
SRCFILE=$(BASE_DIR)/pcaplib.c
OBJFILE=$(BASE_DIR)/pcaplib.o
PCAPLIBRARY=$(BASE_DIR)/pcaplib.so
CFLAGS=-pthread -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -fPIC -I/usr/include/python2.7 
LDFLAGS=-pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-Bsymbolic-functions -Wl,-z,relro -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -D_FORTIFY_SOURCE=2 -g -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security $(OBJFILE) -lcrypto -lpcap

all: $(PCAPLIBRARY)

$(PCAPLIBRARY): $(OBJFILE)
	x86_64-linux-gnu-gcc $(LDFLAGS) -o $(PCAPLIBRARY)

$(OBJFILE): $(SRCFILE)
	x86_64-linux-gnu-gcc $(CFLAGS) -c $(SRCFILE) -o $(OBJFILE)


test: $(PCAPLIBRARY)
	cd $(BASE_DIR) && ipython -i

clean:
	rm -fR $(OBJFILE)
	rm -fR $(PCAPLIBRARY)

