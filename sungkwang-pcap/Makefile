CC      = gcc
CFLAGS  = -Wall -Wextra -g
LDFLAGS = -lpcap -pthread
TARGET  = my_pcap_app

SRCS    = main.c packet_handler.c inject_redirect.c inject_rst.c utils.c uds_thread.c clean_thread.c ai_worker_thread.c
HEADERS = pcap_project.h
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all run clean