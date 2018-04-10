
	

CC=gcc
OBJ=checksum.o test.o

%.o: %.c 
	$(CC) -c -o $@ $< 

main: $(OBJ)
	gcc -o $@ $^ 

clean: 
	rm -f main *.o
