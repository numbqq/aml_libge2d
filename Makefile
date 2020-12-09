export CROSS_COMPILE=aarch64-linux-gnu-
#export CROSS_COMPILE=/opt/gcc-linaro-6.3.1-2017.02-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
CC = $(CROSS_COMPILE)gcc

CFLAGS += -I./libge2d/include/
CFLAGS += -I./libge2d/kernel-headers/linux/
LIBDIR:= ./libge2d
LIBIONDIR += ../aml_libion/
FEATURE_TEST := ge2d_feature_test
CHIP_CHECK := ge2d_chip_check

.PHONY : clean all

all:
	$(MAKE) -C $(LIBDIR)
	$(CC) $(CFLAGS) -L$(LIBDIR) -L$(LIBIONDIR) -lion -lpthread -lge2d $(addsuffix .c,$(FEATURE_TEST)) -o $(FEATURE_TEST)
	$(CC) $(CFLAGS) -L$(LIBDIR) -L$(LIBIONDIR) -lion -lpthread -lge2d $(addsuffix .c,$(CHIP_CHECK)) -o $(CHIP_CHECK)

clean:
	$(MAKE) -C $(LIBDIR) clean
	rm -f $(LIBDIR)/libge2d.so
	rm -f $(FEATURE_TEST) $(CHIP_CHECK)
