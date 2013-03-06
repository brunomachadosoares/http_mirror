CC      = gcc
CFLAGS  = -g -I/axs/include -DLINUX -Wall -O2 `pkg-config glib-2.0 --cflags` -DSTANDALONE

LIBS    = `pkg-config glib-2.0 --libs` \
				-lpcap \
                -lXmu  \
                -lX11 


BIN     = http_mirror
OBJS    = sniff.o remote.o
HEADERS = sniff.h remote.h

all:$(BIN)

$(BIN): $(HEADERS) $(OBJS) Makefile
	$(CC) $(OBJS) -o $@ $(LIBS) $(CFLAGS)

clean:
	rm -rf $(BIN) *.o
