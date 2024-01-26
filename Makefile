CC=gcc
OBJS=main.o pkt_handler.o
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ -lpcap

clean:
	rm -f $(OBJS)


