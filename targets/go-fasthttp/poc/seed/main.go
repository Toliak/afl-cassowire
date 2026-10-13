// Crash-reproduction template for the fasthttp v1.59.0 normalizeHeaderValue bug
// (fixed in v1.60.0, commit b8969ed8 / PR #1963).
//
// It replays the exact fuzz harness flow (FuzzResponseReadLimitBody):
//
//	res := fasthttp.AcquireResponse()
//	defer fasthttp.ReleaseResponse(res)
//	_ = res.ReadLimitBody(bufio.NewReader(bytes.NewReader(body)), maxBodySize)
//
// PASTE YOUR BASE64 PAYLOAD INTO `payloadB64` BELOW (or pass it as argv[1],
// or pipe it to stdin). Expected payload format, same as the harness:
//
//	base64( body || uint16le(maxBodySize) )
//
// i.e. the last 2 decoded bytes are the little-endian maxBodySize and
// everything before them is the raw HTTP response fed to the parser.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/valyala/fasthttp"
)

// >>> PASTE THE CORRECT BASE64 STRING HERE <<<
// (placeholder below = the README/OSS-Fuzz seed; it does NOT panic on
// pristine v1.59.0, it only exercises the same code path)
const payloadB64 = "oeYAdyAyClRyYW5zZmVyLUVuY29kaW5nOmlka7AKCjANCiA6MAogOgogOgogPgAAAAAAAAAgICAhICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiA6CiA6CiAgOgogOgogYDogCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogOgogOgogIDoKIDoKIGA6IAoKIDoKBSAgOgogOgogOgogOgogIDoKIDoKIGA6IAAgIAA6CiA6CiA6CjoKIDoKIDoWCiAyIOgKIDogugogOjAKIDoKIDoKBSAgOgogOgogOgogOgogIDoKIDoKIGA6IAAgIAAAAAAAAABaYQ=="

func main() {
	payload := payloadB64

	// allow: go run ./poc/seed <base64> | cat payload.b64 | go run ./poc/seed
	if len(os.Args) > 1 {
		payload = strings.TrimSpace(os.Args[1])
	} else {
		stdin, _ := io.ReadAll(bufio.NewReader(os.Stdin))
		if s := strings.TrimSpace(string(stdin)); s != "" {
			payload = s
		}
	}

	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "base64 decode failed: %v\n", err)
		os.Exit(1)
	}
	if len(b) < 3 {
		fmt.Fprintf(os.Stderr, "payload too short: %d bytes\n", len(b))
		os.Exit(1)
	}

	body := b[:len(b)-2]
	maxBodySize := int(binary.LittleEndian.Uint16(b[len(b)-2:]))

	fmt.Fprintf(os.Stderr, "body len: %d, maxBodySize: %d\n", len(body), maxBodySize)
	fmt.Fprintln(os.Stderr, "feeding to Response.ReadLimitBody (fuzz harness flow)...")

	res := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(res)

	// A panic here (normalizeHeaderValue, fasthttp_src/header.go) is the bug.
	_ = res.ReadLimitBody(bufio.NewReader(bytes.NewReader(body)), maxBodySize)

	fmt.Fprintln(os.Stderr, "no panic: parser returned without crashing")
}
