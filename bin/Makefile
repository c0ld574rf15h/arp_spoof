CC = gcc
ARC = libarp.a
OBJS = address.o filter.o packet.o utils.o

$(ARC) : $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

%.o : %.c
	$(CC) -o $@ -c -I../include/ $<

clean:
	rm -f *.o $(ARC)