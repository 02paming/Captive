CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude
LDFLAGS = -lpcap -pthread -rdynamic   # -rdynamic: 죽었을 때 함수 이름이 보이게

# 폴더 변수 지정
SRC_DIR   = src
INC_DIR   = include
BUILD_DIR = build
BIN_DIR   = bin

# 최종 실행 파일 이름 및 경로
TARGET  = $(BIN_DIR)/my_pcap_app

# src 폴더 안의 모든 c 파일 목록
SRCS    = $(SRC_DIR)/main.c \
          $(SRC_DIR)/init_engine.c \
          $(SRC_DIR)/hash_table.c \
          $(SRC_DIR)/uds_utils.c \
          $(SRC_DIR)/packet_handler.c \
          $(SRC_DIR)/inject_redirect.c \
          $(SRC_DIR)/inject_rst.c \
          $(SRC_DIR)/uds_thread.c \
          $(SRC_DIR)/clean_thread.c \
          $(SRC_DIR)/ai_worker_thread.c \
          $(SRC_DIR)/log_thread.c

# src/xxx.c 를 build/xxx.o 로 치환하는 마법의 명령어
OBJS    = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

all: $(TARGET)

# 1. 최종 실행 파일 빌드 (bin 폴더 안에 생성)
$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 2. 오브젝트 파일 빌드 (build 폴더 안에 생성)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 3. build, bin 폴더가 없으면 자동으로 생성해주는 규칙
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

# 5. [측정] 해시 테이블 벤치마크 (실제 src/hash_table.c 를 그대로 링크, 엔진과 같은 CFLAGS)
BENCH = $(BIN_DIR)/hash_bench
bench: $(BENCH)
$(BENCH): bench/hash_bench.c $(SRC_DIR)/hash_table.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TARGET)
	sudo ./$(TARGET)

# 4. 청소할 때는 build와 bin 폴더 자체를 날려버림
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all run clean bench