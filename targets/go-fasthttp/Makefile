include ../_mk/git.mk
include ../_mk/aflpp.mk
include ../_mk/fuzz.mk

GO_FASTHTTP_URL := https://github.com/valyala/fasthttp
GO_FASTHTTP_BRANCH := v1.59.0

BUILD_MAKE_ARGS := -j$(nproc)

src:
	$(GIT_CLONE_CMD) $(GO_FASTHTTP_URL) --branch "$(GO_FASTHTTP_BRANCH)" $@

BIN_DIR := bin

helloworld:
	go build -trimpath -o $(BIN_DIR)/helloworld ./cmd/helloworld

clean:
	rm -rf $(BIN_DIR)

.PHONY: helloworld clean
