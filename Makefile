CC=gcc
OBJS=main.o ./src/pkt_handler.o
LDFLAGS=-lpcap
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

main.o:./hdr/pkt_handler.h
./src/pkt_handler.o:./hdr/pkt_handler.h

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)

