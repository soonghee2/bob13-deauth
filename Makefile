CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lpcap

TARGET = deauth
SRCS = deauth.cpp

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
