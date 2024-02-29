CC=gcc
OBJS=main.o ./src/ui.o ./src/pkt_parser.o ./src/print.o
LDFLAGS=-lpcap -lpthread
TARGET=main.out

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

debug:$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS) -g

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)

main.o:./hdr/ui.h 
./src/ui.o:./hdr/ui.h
./src/pkt_parser.o:./hdr/pkt_parser.h ./hdr/protocol.h
./src/print.o:./hdr/print.h ./hdr/pkt_parser.h ./hdr/protocol.h


