CFLAGS ?= -O2 -g -Wall -W -Wno-unused-function
LDLIBS ?= -lrt -lpcap -pthread

wperf: wperf.o
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS)

static:
	$(MAKE) LDFLAGS="$(LDFLAGS) -static" wperf

clean:
	rm -f wperf.o wperf
