package link

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	l, err := Parse(" wdtt://185.225.201.69:56000:56001:9000:pa55-word:https://vk.com/call/join/AbC_1?x=1,DEF ")
	if err != nil {
		t.Fatal(err)
	}
	if l.Host != "185.225.201.69" || l.DTLSPort != 56000 || l.WGPort != 56001 || l.LocalPort != 9000 || l.Password != "pa55-word" {
		t.Fatalf("%+v", l)
	}
	if strings.Join(l.Hashes, ",") != "AbC_1,DEF" || l.Peer() != "185.225.201.69:56000" {
		t.Fatalf("%+v", l)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	l.ServerKey = key
	l2, err := Parse(l.String())
	if err != nil || string(l2.ServerKey) != string(key) || strings.Join(l2.Hashes, ",") != "AbC_1,DEF" {
		t.Fatalf("round trip %+v %v", l2, err)
	}
	// Standard base64 is accepted too.
	l3, err := Parse("wdtt://h:1:2:3:pw:H1,H2?pk=AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tk=")
	if err != nil || len(l3.ServerKey) != 32 || strings.Join(l3.Hashes, ",") != "H1,H2" {
		t.Fatalf("std base64 %+v %v", l3, err)
	}
	for _, bad := range []string{"", "http://x", "wdtt://h:1:2:3:pw", "wdtt://h:0:2:3:pw:H", "wdtt://h:1:2:3::H", "wdtt://h:1:2:3:pw:https://example.com/"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
