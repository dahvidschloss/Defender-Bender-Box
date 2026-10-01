CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -O2 -Wall -Wextra -municode
LDLIBS  := -lkernel32 -luser32

TARGET  := loader.exe
SRCS    := loader.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
