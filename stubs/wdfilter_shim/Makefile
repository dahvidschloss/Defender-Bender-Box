CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -O2 -Wall -Wextra -shared -static-libgcc \
           -Wl,--enable-stdcall-fixup \
           -Wl,--exclude-all-symbols
LDLIBS  := -lkernel32 -lntdll -ladvapi32 -lrpcrt4

TARGET  := wdfilter_shim.dll
SRCS    := wdfilter_shim.c iat_hook.c

all: $(TARGET)

$(TARGET): $(SRCS) iat_hook.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
