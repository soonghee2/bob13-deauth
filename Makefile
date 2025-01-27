CC = g++
CFLAGS = -Wall -Wextra -std=c++17
TARGET = deauth
SRC = deauth.cpp
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
