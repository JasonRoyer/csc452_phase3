# Version 2.0
# This is a sample Makefile for Phase 2. 
#
#	make		(makes libphase2.a and all tests)
#   make phase2 ditto
#
#	make testN 	(makes testN)
#	make testN.out	(runs testN and puts output in testN.out)
#	make tests	(makes all testN.out files, i.e. runs all tests)
#	make tests_bg	(runs all tests in the background)
#
#	make testN.v	(runs valgrind on testN and puts output in testN.v)
#	make valgrind	(makes all testN.v files, i.e. runs valgrind on all tests)
#
#	make clean	(removes all files created by this Makefile)

ifndef PREFIX
	PREFIX = $(HOME)
endif

# Set to the part (A or B) of the phase.
PART = A

# Set to Phase 3 version
PHASE3_VERSION = 3.2

# Set to Phase 2 version
PHASE2_VERSION = 2.6

# Set to USLOSS version
USLOSS_VERSION = 3.6

# Set to Phase 1 version
PHASE1_VERSION = 1.8

# Set to user library version (same as USLOSS version by default)
USER_VERSION = $(USLOSS_VERSION)

# All .c files in this directory are included in the Phase 3 library.
SRCS = $(wildcard *.c)

# Each .c file in the tests$(PART) subdirectory is a separate test case.
TESTS = $(patsubst %.c,%,$(wildcard tests$(PART)/*.c))

# Change this if you want to change the arguments to valgrind.
VGFLAGS = --track-origins=yes --leak-check=full --max-stackframe=100000

# Change this if you need to link against additional libraries (probably not).
LIBS = -lphase$(PHASE1_VERSION) -lusloss$(USLOSS_VERSION) -lphase$(PHASE2_VERSION) \
-lphase$(PHASE3_VERSION) -luser$(USER_VERSION) -ldisk$(USLOSS_VERSION)

# Change this if you want change which flags are passed to the C compiler.
CFLAGS += -Wall -g -std=gnu99
#CFLAGS += -DDEBUG

# You shouldn't need to change anything below here. 

LIB_DIR = $(PREFIX)/lib
INC_DIR	= $(PREFIX)/include
INSTALL_DATA = /usr/bin/install -c

PHASE = phase3

TARGET = libphase$(PHASE3_VERSION).a

INCLUDES = -I$(INC_DIR) -I.

ifeq ($(shell uname),Darwin)
	DEFINES += -D_XOPEN_SOURCE
	OS = macosx
	CFLAGS += -Wno-int-to-void-pointer-cast -Wno-extra-tokens -Wno-unused-label -Wno-unused-function
else
	OS = linux
	CFLAGS += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wno-unused-but-set-variable
endif

CC=gcc
LD=gcc
AR=ar    
CFLAGS += $(INCLUDES) $(DEFINES) -Werror -DPHASE_3
LDFLAGS = -L$(LIB_DIR) -L.
COBJS = ${SRCS:.c=.o}
DEPS = ${COBJS:.o=.d}
TSRCS = {$TESTS:=.c}
TOBJS = ${TESTS:=.o}
TOUTS = ${TESTS:=.out}
TVS = ${TESTS:=.v}

# The following is to deal with circular dependencies between the USLOSS and phase1
# libraries. Unfortunately the linkers handle this differently on the two OSes.
# Also add flags to warn about duplicate global variables and to make warnings fatal.

ifeq ($(OS), macosx)
	LIBFLAGS = -Wl,-all_load $(LIBS)
	# The following only works for dynamic libraries. TODO make it work with static.
	LDFLAGS += -Wl,-warn_commons -Wl,-fatal_warnings
else
	LIBFLAGS = -Wl,--start-group $(LIBS) -Wl,--end-group
	LDFLAGS +=  -Wl,--warn-common -Wl,--fatal-warnings
endif

%.d: %.c
	$(CC) -c $(CFLAGS) -MM -MF $@ $<

.PHONY: all tests $(PHASE)

all: $(PHASE)

$(PHASE): $(TARGET) $(TESTS)

lib: $(TARGET)


$(TARGET):  $(COBJS)
	$(AR) -r $@ $^

tests: $(TOUTS)

# Remove implicit rules so that "make phaseN" doesn't try to build it from phaseN.c or phaseN.o
% : %.c

% : %.o

%.out: %
	./$< 1> $@ 2>&1

$(TESTS):   %: $(TARGET) %.o Makefile
	- $(LD) $(LDFLAGS) -o $@ $@.o $(LIBFLAGS)

clean:
	rm -f $(COBJS) $(TARGET) $(TOBJS) $(TESTS) $(DEPS) $(TVS) *.out tests$(PART)/*.out p3/*.o p3/p3stubsTest

%.d: %.c
	$(CC) -c $(CFLAGS) -MM -MF $@ $<

valgrind: $(TVS)

%.v: %
	valgrind $(VGFLAGS) ./$< 1> $@ 2>&1

p3/p3stubsTest: $(STUBS) p3/p3stubsTest.o
	$(LD) $(LDFLAGS) -o $@ $^

-include $(DEPS)
