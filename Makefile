CC     = gcc
CFLAGS = -Wall -O2 -g -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LDLIBS = 
 
TARGET = tssplitter_lite
OBJS   = tssplitter_lite.o 

all: $(TARGET)

tssplitter_lite.o: tssplitter_lite.c portable.h

$(TARGET): $(OBJS)
	$(CC) $(LDLIBS) -o $(TARGET) $(OBJS)

clean:
	rm -f *.o
	rm -f $(TARGET)
