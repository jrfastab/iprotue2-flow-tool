CFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 libgvc --cflags` -Wall -g -O2
LDFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 libgvc --libs`

all: flow flowd

flow: flow.c
	gcc -c $(CFLAGS) flowlib.c flow.c
	gcc flow.o flowlib.o $(LDFLAGS) -o flow

flowd: ./test/flowd.c
	gcc -c $(CFLAGS) flowlib.c ./test/flowd.c
	gcc flowd.o flowlib.o $(LDFLAGS) -o flowd

clean:
	rm -rf *.o flow flowd
