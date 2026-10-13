package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/valyala/fasthttp"
)

var addr = flag.String("addr", "127.0.0.1:8080", "TCP address to listen to")

func main() {
	flag.Parse()

	if err := fasthttp.ListenAndServe(*addr, requestHandler); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hello, world!\n\n")
	fmt.Fprintf(ctx, "Request method is %q\n", ctx.Method())
	fmt.Fprintf(ctx, "RequestURI is %q\n", ctx.RequestURI())
	fmt.Fprintf(ctx, "Host is %q\n", ctx.Host())
	fmt.Fprintf(ctx, "Your ip is %q\n\n", ctx.RemoteIP())

	ctx.SetContentType("text/plain; charset=utf8")
}
