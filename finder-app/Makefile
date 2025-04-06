CROSS_COMPILE ?=

ifeq ($(origin CC), environment)
  CC := $(CC)
else
  CC := $(CROSS_COMPILE)gcc
endif


all: build

build:
	$(CC) -Wall writer.c -o writer

clean:
	rm -f writer *.o
