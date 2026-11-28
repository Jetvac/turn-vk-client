package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

// socksClient greets the proxy offering methods and, when asked, logs in;
// it returns the proxy's answer to the greeting and to the login.
func socksClient(t *testing.T, addr string, methods []byte, user, pass string) (net.Conn, []byte, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(append([]byte{5, byte(len(methods))}, methods...))
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return c, nil, nil
	}
	if greet[1] != 2 {
		return c, greet, nil
	}
	req := append([]byte{1, byte(len(user))}, user...)
	req = append(append(req, byte(len(pass))), pass...)
	c.Write(req)
	login := make([]byte, 2)
	io.ReadFull(c, login)
	return c, greet, login
}

func TestSOCKSPassword(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	auth, err := parseSocksAuth("")
	if err != nil || auth.user == "" || len(auth.pass) < 16 {
		t.Fatalf("random password: %+v %v", auth, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var d net.Dialer
	go serveSOCKSOn(ctx, ln, auth, d.DialContext)
	addr := ln.Addr().String()

	// No password offered: refused.
	c, greet, _ := socksClient(t, addr, []byte{0}, "", "")
	c.Close()
	if !bytes.Equal(greet, []byte{5, 0xff}) {
		t.Fatalf("no password: %v", greet)
	}
	// A wrong one: refused.
	c, _, login := socksClient(t, addr, []byte{0, 2}, auth.user, "guess")
	c.Close()
	if !bytes.Equal(login, []byte{1, 1}) {
		t.Fatalf("wrong password: %v", login)
	}
	// The right one: a connection through.
	c, _, login = socksClient(t, addr, []byte{0, 2}, auth.user, auth.pass)
	defer c.Close()
	if !bytes.Equal(login, []byte{1, 0}) {
		t.Fatalf("right password: %v", login)
	}
	port := echo.Addr().(*net.TCPAddr).Port
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("connect: %v %v", reply, err)
	}
	c.Write([]byte("ping"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo: %q %v", got, err)
	}

	for _, s := range []string{"user", ":pass", "user:", "none"} {
		a, err := parseSocksAuth(s)
		if (s == "none") != (err == nil) || a.user != "" {
			t.Errorf("%q: %+v %v", s, a, err)
		}
	}
	if a, err := parseSocksAuth("me:p:w"); err != nil || a.user != "me" || a.pass != "p:w" {
		t.Errorf("me:p:w: %+v %v", a, err)
	}
}
