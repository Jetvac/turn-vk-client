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
	for _, bad := range []string{"", "http://x", "wdtt://h:1:2:3:pw", "wdtt://h:0:2:3:pw:H", "wdtt://h:1:2:3::H", "wdtt://h:1:2:3:pw:https://example.com/"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
