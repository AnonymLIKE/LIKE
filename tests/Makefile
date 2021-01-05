IDIR = ../include
BUILDDIR = ../build
SRCDIR = ../src

CC = clang
#CFLAGS=-I$(IDIR) 
CFLAGS=-I$(IDIR) -Wall -Wextra -pedantic
#CFLAGS=-I$(IDIR) -Wall -Werror -Wextra -pedantic -v
#CFLAGS=-I$(IDIR) -Wall -Werror -Wextra -pedantic -v -g
LDFLAGS := -lmcl -lmclbn512 -lgmp -lgmpxx -lcrypto -luuid -lgsl -lm
EXEC = like_mesure

SRC = $(wildcard $(SRCDIR)/*.c) $(wildcard *.c) 
OBJ = $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRC))

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c 
	$(CC) $(CFLAGS) -c -o $@ $< $(LDFLAGS)
