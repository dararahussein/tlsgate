BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf

.PHONY: xdp run test lint loadtest clean

xdp:
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/xdp_blocklist.bpf.c -o bpf/xdp_blocklist.bpf.o

run:
	python -m tlsgate.proxy.server

test:
	pytest tests/ -v

lint:
	ruff check src/ tests/
	mypy src/

loadtest:
	python -m benchmarks.load_runner

clean:
	rm -f bpf/*.o
