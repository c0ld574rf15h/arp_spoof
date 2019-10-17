EXE = arp_spoof
CC = gcc

$(EXE) : main.o
	$(CC) -L ../bin -o $(EXE) main.o -larp -lpcap

main.o : main.c
	$(CC) -o main.o -c -I../include main.c

clean:
	rm -f main.o $(EXE)