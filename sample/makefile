
PROGRAM = sample
CFLAGS = -g -Wall -I ../peg/include
LIB = ../peg/libinhertpeg.a

$(PROGRAM): sample.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

clean:
	rm -f $(PROGRAM)

