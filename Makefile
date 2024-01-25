CC=gcc
OBJS=main.o pkt_handler.o atk_detector.o pkt_io.o
TARGET=main.out

$(TARGET):$(OBJS)
	$(CC) -o $@ $(OBJS)

main.o:header/pkt_handler.h
pkt_handler.o:header/protocol.h header/pkt_handler.h header/pkt_io.h header/atk_detector.h
atk_detector.o:header/atk_detector.h
pkt_io.o:header/pkt_io.h
