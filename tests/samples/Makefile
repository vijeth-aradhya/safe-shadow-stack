# tools
CC := gcc
RM := rm -f
CP := cp

# flags
CFLAGS := -ggdb -fno-stack-protector
LDFLAGS :=
LDLIBS :=

# sources
tsources := program1.c program2.c program3.c
targets := program1 program2 program3

# gmake magic
.PHONY: default all clean generate

#targets
default: all
all: $(targets)

generate:  
	./base/generatesrc.py

install: $(targets)
	execstack -s program1
	execstack -s program2

clean:
	$(RM) $(targets) $(sources:.c=.o) $(tsources)

