MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(realpath $(MAKEFILE_DIR)/../../)


all: .bashrc


bin:
	mkdir -p ./bin
	ln -s "$(PROJECT_DIR)/tools/http_throughput/build/http_bench" ./bin/http_bench
	ln -s "$(PROJECT_DIR)/aflpp/src/distrib/bin/afl-clang-lto" ./bin/afl-clang-lto
	ln -s "$(PROJECT_DIR)/aflpp/src/distrib/bin/afl-clang-lto++" ./bin/afl-clang-lto++
	ln -s "$(PROJECT_DIR)/aflpp/src/distrib/bin/afl-clang-fast" ./bin/afl-clang-fast
	ln -s "$(PROJECT_DIR)/aflpp/src/distrib/bin/afl-clang-fast++" ./bin/afl-clang-fast++
	ln -s "$(PROJECT_DIR)/afl-cassowire/build/afl-cassowire" ./bin/afl-cassowire


.bashrc: bin
	echo 'export PATH="$(MAKEFILE_DIR)/bin:$$PATH"' > ./.bashrc


clean:
	rm -rf ./bin
	rm -f ./.bashrc


.PHONY: all clean