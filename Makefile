CC=gcc
OBJS=main.o ./src/controller.o ./src/pkt_handler.o ./src/pkt_parser.o ./src/print.o
LDFLAGS=-lpcap -lpthread
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

main.o:./hdr/controller.h ./hdr/pkt_handler.h 
./src/controller.o:./hdr/controller.h
./src/pkt_handler.o:./hdr/pkt_handler.h
./src/pkt_parser.o:./hdr/pkt_parser.h ./hdr/protocol.h
./src/print.o:./hdr/print.h ./hdr/pkt_handler.h ./hdr/protocol.h

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)