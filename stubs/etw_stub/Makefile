CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -O2 -Wall -Wextra -shared -static-libgcc
LDLIBS  := -lkernel32 -ladvapi32

TARGET  := etw_stub.dll
SRCS    := etw_stub.c ../wdfilter_shim/iat_hook.c
INCS    := -I../wdfilter_shim

all: $(TARGET)

$(TARGET): $(SRCS) ../wdfilter_shim/iat_hook.h
	$(CC) $(CFLAGS) $(INCS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
