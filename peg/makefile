
.SUFFIXES: .c

CC      = gcc
PROGRAM = libinhertpeg.a
CFLAGS  = -g -Wall -I include
FILES   = peg.o
OBJS    = $(FILES:%=lib/%)
SRCS    = $(OBJS:%.o=src/%.c)

${PROGRAM}:$(OBJS)
	ar rv $@ $?
	ranlib $@

lib/%.o:src/%.c include/inhert/%.h
	if [ ! -d lib ];then \
		mkdir -p lib;    \
	fi
	$(CC) $(CFLAGS) -o lib/$*.o -c $<

clean:
	rm -f $(OBJS)
	rm -f $(PROGRAM)

