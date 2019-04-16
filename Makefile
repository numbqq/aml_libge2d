# export CROSS_COMPILE=arm-linux-gnueabihf-
# export CROSS_COMPILE=/opt/gcc-linaro-6.3.1-2017.02-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
# CC = $(CROSS_COMPILE)gcc

CFLAGS += -I./libge2d/include/
CFLAGS += -I./libge2d/kernel-headers/linux/
LIBDIR:= ./libge2d
SRC  := $(wildcard *.c)
TEST := ge2d_feature_test

.PHONY : clean all

all:
	$(MAKE) -C $(LIBDIR)
	$(CC) $(CFLAGS) $(SRC) -L$(LIBDIR) -lge2d -o $(TEST)

clean:
	rm -f $(LIBDIR)/libge2d.so
	rm -f $(TEST)
