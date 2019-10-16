CC = gcc
ARC = arplib.a
OBJS = address.o filter.o packet.o utils.o

$(ARC) : $(OBJS)
	$(AR) $(ARFLAGS) $a $(OBJS)

%.o : %.c
	$(CC) -o $@ -c -I../include/ $<

clean:
	rm -f *.o $(ARC)