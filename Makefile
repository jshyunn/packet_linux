CC=gcc
OBJS=main.o ./src/pkt_io.o ./src/pkt_handler.o
LDFLAGS=-lpcap -lpthread
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

main.o:./hdr/pkt_io.h
./src/pkt_io.o:./hdr/pkt_io.h
./src/pkt_handler.o:./hdr/pkt_handler.h

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)

