CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -O2 -Wall -Wextra -municode
LDLIBS  := -lkernel32

TARGET  := mpscan.exe
SRCS    := mpscan.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
