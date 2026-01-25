CROSS_COMPILE ?=

ifeq ($(origin CC), environment)
  CC := $(CC)
else
  CC := $(CROSS_COMPILE)gcc
endif

CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread


all: build

build:
	$(CC) $(CFLAGS) -Wall -g aesdsocket.c -o aesdsocket $(LDFLAGS)
	# $(CC) $(CFLAGS) -Wall -fsanitize=thread -g aesdsocket.c -o aesdsocket

clean:
	rm -f aesdsocket *.o
