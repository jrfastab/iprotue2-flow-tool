CFLAGS=`pkg-config libnl-3.0 libnl-route-3.0 libnl-cli-3.0 libgvc --cflags`  \
	-Wall -g -O2 -std=c99 -O2 -D_GNU_SOURCE				     \
	-pedantic -Wextra -Wformat=2 -Wlogical-op -Wpointer-arith	     \
	-Wnested-externs -Wbad-function-cast -Wconversion -Wcast-qual	     \
	-Wcast-align -Wstrict-prototypes -Wmissing-declarations		     \
	-Wmissing-include-dirs  -Wdeclaration-after-statement		     \
	-Wmissing-prototypes -Wold-style-definition -Wextra

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
