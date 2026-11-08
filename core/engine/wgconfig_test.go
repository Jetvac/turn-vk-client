package engine

import (
	"strings"
	"testing"
)

// The exact format WDTT servers send.
const serverConf = `[Interface]
PrivateKey = YNqHbfBQKaGvzefSSpPBkO6yAP1tY3e8C/JL4z4wpXQ=
Address = 10.66.66.7/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:9000
PersistentKeepalive = 25`

func TestParseWGConfig(t *testing.T) {
	c, err := ParseWGConfig(serverConf)
	if err != nil {
		t.Fatal(err)
	}
	if c.Address.String() != "10.66.66.7/32" || c.MTU != 1280 || len(c.DNS) != 1 || c.Keepalive != 25 {
		t.Fatalf("%+v", c)
	}
	u, err := c.uapi()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=60da876d", "public_key=1c8828f7", "endpoint=wdtt:0", "allowed_ip=0.0.0.0/0", "persistent_keepalive_interval=25"} {
		if !strings.Contains(u, want) {
			t.Errorf("uapi lacks %q:\n%s", want, u)
		}
	}
	if _, err := ParseWGConfig("[Interface]\nAddress = 10.0.0.2/32"); err == nil {
		t.Error("want error without keys")
	}
}
