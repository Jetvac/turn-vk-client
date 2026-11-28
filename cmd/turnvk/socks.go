package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// socksAuth is the user name and password a client must give (RFC 1929);
// empty, none is asked. Without one any program on the computer could use
// the proxy, and through it learn the VPN's exit address: the RKN-style
// VPN detectors scan the local ports for such proxies.
type socksAuth struct{ user, pass string }

// parseSocksAuth reads -socks-auth: "user:password", "none", or "" for a
// random password.
func parseSocksAuth(s string) (socksAuth, error) {
	switch s {
	case "none":
		return socksAuth{}, nil
	case "":
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return socksAuth{}, err
		}
		return socksAuth{user: "turnvk", pass: hex.EncodeToString(b)}, nil
	}
	u, p, ok := strings.Cut(s, ":")
	if !ok || u == "" || p == "" || len(u) > 255 || len(p) > 255 {
		return socksAuth{}, errors.New("-socks-auth: user:password (up to 255 characters each) or none")
	}
	return socksAuth{u, p}, nil
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// serveSOCKS is a minimal SOCKS5 server (CONNECT only) that dials through
// the tunnel.
func serveSOCKS(ctx context.Context, addr string, auth socksAuth, dial dialFunc) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("SOCKS5: %v", err)
		return
	}
	serveSOCKSOn(ctx, ln, auth, dial)
}

func serveSOCKSOn(ctx context.Context, ln net.Listener, auth socksAuth, dial dialFunc) {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			if err := socksConn(ctx, c, auth, dial); err != nil && !errors.Is(err, io.EOF) {
				log.Printf("SOCKS5 %s: %v", c.RemoteAddr(), err)
			}
		}()
	}
}

// socksLogin checks the client's user name and password (RFC 1929).
func socksLogin(c net.Conn, auth socksAuth) error {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 1 {
		return errors.New("bad password request")
	}
	u := make([]byte, h[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return err
	}
	p := make([]byte, pl[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(u, []byte(auth.user))&subtle.ConstantTimeCompare(p, []byte(auth.pass)) != 1 {
		c.Write([]byte{1, 1})
		return errors.New("wrong user name or password")
	}
	_, err := c.Write([]byte{1, 0})
	return err
}

func socksConn(ctx context.Context, c net.Conn, auth socksAuth, dial dialFunc) error {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 {
		return errors.New("not SOCKS5")
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	if auth.user == "" {
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return err
		}
	} else {
		if !slices.Contains(methods, 2) {
			c.Write([]byte{5, 0xff})
			return errors.New("the client offers no password")
		}
		if _, err := c.Write([]byte{5, 2}); err != nil {
			return err
		}
		if err := socksLogin(c, auth); err != nil {
			return err
		}
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return err
	}
	if req[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return errors.New("only CONNECT is supported")
	}
	var host string
	switch req[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return err
		}
		host = net.IP(a[:]).String()
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return err
		}
		host = net.IP(a[:]).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = string(b)
	default:
		return errors.New("bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:]))))
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	up, err := dial(dctx, "tcp", target)
	cancel()
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
	go func() { io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
