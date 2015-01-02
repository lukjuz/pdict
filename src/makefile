IDIR =./include

CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR =./lib

LIBS=-lcrypt -pthread -Wall -lcuda

_DEPS = thread_data.h manager.h reader.h comparer.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = thread_data.o manager.o reader.o comparer.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pdict: $(OBJ)
	$(CC) -o $@ pdict.c $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 