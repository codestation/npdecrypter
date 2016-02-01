TARGET = npdecrypter
OBJS =  main.o hook.o imports.o exports.o decrypter.o logger.o kmalloc.o
LIBS =
CFLAGS = -O2 -G0 -Wall -std=c99 -DKPRINTF_ENABLED
CXXFLAGS = $(CFLAGS)
ASFLAGS = $(CFLAGS)

USE_KERNEL_LIBC = 1
USE_KERNEL_LIBS = 1

PSP_FW_VERSION=500

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build_prx.mak
