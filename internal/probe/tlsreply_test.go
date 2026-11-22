package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSReplyDetectedFromFirstBytes(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
		want  bool
	}{
		{"alert", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}, true},
		{"handshake", []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00}, true},
		{"postgres error", []byte("E\x00\x00\x00\x08invalid"), false},
		{"banner", []byte("SSH-2.0-OpenSSH_9.6\r\n"), false},
		{"0x16 without version", []byte{0x16, 0x41, 0x42}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, 1024)
				conn.Read(buf)
				conn.Write(c.reply)
			}()
			port := ln.Addr().(*net.TCPAddr).Port
			p := &Prober{Timeout: 5 * time.Second}
			_, err = p.Probe(context.Background(), "127.0.0.1", port, false, "")
			if err == nil {
				t.Fatal("probe succeeded, want an error")
			}
			if got := TLSReply(err); got != c.want {
				t.Fatalf("TLSReply(%v) = %v, want %v", err, got, c.want)
			}
		})
	}
}

func TestTLSReplyFalseForHTTPAndHTTPSWorks(t *testing.T) {
	if TLSReply(nil) {
		t.Fatal("TLSReply(nil) = true")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<title>ok</title>"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	s, err := (&Prober{Timeout: 5 * time.Second}).Probe(context.Background(), "127.0.0.1", port, true, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if s.HTTP.Title != "ok" || s.HTTP.TLS == nil {
		t.Fatalf("https probe = %+v", s.HTTP)
	}
}
