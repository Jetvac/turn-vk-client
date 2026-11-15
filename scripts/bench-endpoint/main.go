// Command bench-endpoint is the speed-test endpoint for scripts/bench.sh.
// Run it on the test server, on the server's tunnel address, so that
// downloads and uploads measure the tunnel rather than the internet:
//
//	bench-endpoint -listen 10.66.67.1:8081
//
// GET /?bytes=N sends N zero bytes; POST reads and discards the body.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
)

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func main() {
	listen := flag.String("listen", "10.66.67.1:8081", "address to listen on")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte("ok"))
			return
		}
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || n <= 0 {
			n = 50_000_000
		}
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		_, _ = io.CopyN(w, zeros{}, n)
	})
	log.Fatal(http.ListenAndServe(*listen, nil))
}
