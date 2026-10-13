```
func FuzzResponseReadLimitBody(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Type: aa\r\nContent-Length: 10\r\n\r\n9876543210"), 1024)
	f.Add([]byte(" 0\nTrAnsfer-EnCoding:0\n\n0\r\n1:0\n        00\n 000\n\n"), 24922)
	f.Add([]byte(" 0\n0:\n 0\n :\n"), 1048532)

	// Case found by OSS-Fuzz.
    // This bug fixed in v1.60.0 and later.
    // Current cloned in ./src version is v1.59.0
	b, err := base64.StdEncoding.DecodeString("oeYAdyAyClRyYW5zZmVyLUVuY29kaW5nOmlka7AKCjANCiA6MAogOgogOgogPgAAAAAAAAAgICAhICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiA6CiA6CiAgOgogOgogYDogCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogOgogOgogIDoKIDoKIGA6IAoKIDoKBSAgOgogOgogOgogOgogIDoKIDoKIGA6IAAgIAA6CiA6CiA6CjoKIDoKIDoWCiAyIOgKIDogugogOjAKIDoKIDoKBSAgOgogOgogOgogOgogIDoKIDoKIGA6IAAgIAAAAAAAAABaYQ==")
	if err != nil {
		panic(err)
	}
	f.Add(b[:len(b)-2], int(binary.LittleEndian.Uint16(b[len(b)-2:])))

	f.Fuzz(func(t *testing.T, body []byte, maxBodySize int) {
		if len(body) > 1024*1024 || maxBodySize > 1024*1024 {
			return
		}
		// Only test with a max for the body, otherwise a very large Content-Length will just OOM.
		if maxBodySize <= 0 {
			return
		}

		res := AcquireResponse()
		defer ReleaseResponse(res)

		_ = res.ReadLimitBody(bufio.NewReader(bytes.NewReader(body)), maxBodySize)
	})
}
```