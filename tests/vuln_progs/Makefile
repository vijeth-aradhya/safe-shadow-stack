# tools
CC := gcc
RM := rm -f
CP := cp

# flags
CFLAGS := -ggdb -fno-stack-protector -z execstack
LDFLAGS :=
LDLIBS :=

# sources
tsources := program1.c program2.c
targets := program1 program2

# gmake magic
.PHONY: default all clean generate

#targets
default: all
all: $(targets)

generate:  
	./base/generatesrc.py

install: $(targets)
	execstack -s program1

clean:
	$(RM) $(targets) $(sources:.c=.o)

