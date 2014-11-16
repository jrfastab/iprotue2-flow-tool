CFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 --cflags` -g -O2
LDFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 --libs`

all: flow 

flow: flowlib.o flow.o

clean:
	rm -rf *.o flow
