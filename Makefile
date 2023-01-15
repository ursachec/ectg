CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

.PHONY: clean
clean:
	rm bpf_bpfeb.go bpf_bpfeb.o bpf_bpfel.go bpf_bpfel.o

.PHONY: fmt
fmt:
	go fmt

.PHONY: test
test:
	go test -v ./...
