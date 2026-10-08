CC = gcc
CLANG = clang
CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -O2 -target bpf -g -Wall

LIBBPF_LIBS = -lbpf -lelf -lz

TARGET_BPF = xdp_guard.bpf.o
TARGET_USER = xdp_guard_daemon

all: $(TARGET_BPF) $(TARGET_USER)

$(TARGET_BPF): xdp_guard.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(TARGET_USER): main.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	rm -f $(TARGET_BPF) $(TARGET_USER)