# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb
LDFLAGS :=
LDLIBS :=

# sources
sources := helloworld.c
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

#targets
default: all
all: $(targets)

clean:
	$(RM) $(targets) $(sources:.c=.o)


