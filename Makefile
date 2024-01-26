CC=gcc
C_SRC=$(wildcard *.c)
OBJS=$(C_SRC:.c=.o)
CFLAGS=-I ./hdr -I ./src
LDFLAGS=-lpcap
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS)


