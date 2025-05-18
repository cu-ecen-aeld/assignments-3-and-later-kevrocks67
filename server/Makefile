CROSS_COMPILE ?=

ifeq ($(origin CC), environment)
  CC := $(CC)
else
  CC := $(CROSS_COMPILE)gcc
endif


all: build

build:
	$(CC) -Wall -g aesdsocket.c -o aesdsocket
	# $(CC) -Wall -fsanitize=thread -g aesdsocket.c -o aesdsocket

clean:
	rm -f aesdsocket *.o
