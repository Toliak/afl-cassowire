module pocfasthttp

go 1.21

require github.com/valyala/fasthttp v1.59.0

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
)

replace github.com/valyala/fasthttp => ./fasthttp_src
