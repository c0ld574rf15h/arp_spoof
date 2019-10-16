EXE = arp_spoof
CC = gcc

$(EXE) : main.o
	$(CC) -o $(EXE) main.o -L ../bin

main.o : main.c
	$(CC) -o main.o -c main.c -I../include

clean:
	rm -f main.o $(EXE)