# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb
LDFLAGS :=
LDLIBS :=

# sources
sources := test1.c test2.c test3.c
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

#targets
default: all
all: $(targets)

clean:
	$(RM) $(targets) $(sources:.c=.o)


