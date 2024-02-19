CC=gcc
OBJS=main.o ./src/pkt_io.o ./src/pkt_handler.o ./src/pkt_parser.o
LDFLAGS=-lpcap -lpthread
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

main.o:./hdr/pkt_io.h ./hdr/pkt_handler.h 
./src/pkt_io.o:./hdr/pkt_io.h ./hdr/protocol.h ./hdr/pkt_handler.h
./src/pkt_handler.o:./hdr/pkt_handler.h ./hdr/pkt_parser.h
./src/pkt_parser.o:./hdr/pkt_parser.h ./hdr/protocol.h

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)

