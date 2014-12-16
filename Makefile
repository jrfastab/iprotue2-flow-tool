CFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 libgvc --cflags` -Wall -g -O2
LDFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 libgvc --libs`

all: flow flowd

flow: flowlib.o flow.o
flowd: flowlib.o ./test/flowd.o

clean:
	rm -rf *.o flow flowd
	rm -rf ./test/*.o
