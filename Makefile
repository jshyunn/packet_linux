CC=gcc
OBJS=main.o pkt_handler.o
TARGET=main.out

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $@ $^

clean:
	rm -f $(OBJS)

main.o:hdr/pkt_handler.h main.c
	gcc -c -o main.o main.c -lpcap
pkt_handler.o:hdr/pkt_handler.h src/pkt_handler.c
	gcc -c -o pkt_handler.o src/pkt_handler.c -lpcap
