all: build

prepare:
	meson setup build

build: prepare
	meson compile -C build

clean:
	rm -rf build

.PHONY: prepare build clean all
