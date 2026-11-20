package session

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

// Renewal is due only after renewAfter of real time of which the device
// slept renewSlept: an awake device leaves it to pion.
func TestRenewDue(t *testing.T) {
	var r renewState
	r.mark(0, 0)
	m := int64(time.Minute)
	for _, tc := range []struct {
		wall, mono int64
		want       bool
	}{
		{10 * m, 10 * m, false}, // awake all along
		{m, 0, false},           // asleep, but not long ago
		{2 * m, 2*m - int64(renewSlept), true},
		{2 * m, 2*m - int64(renewSlept) + 1, false},
		{30 * m, m, true},
	} {
		if got := r.due(tc.wall, tc.mono); got != tc.want {
			t.Fatalf("due(%v, %v) = %v", time.Duration(tc.wall), time.Duration(tc.mono), got)
		}
	}
	r.mark(30*m, m)
	if r.due(31*m, m) {
		t.Fatal("due right after a renewal")
	}
}

// renewTURN is a fake TURN server for renew: a script of error codes per
// request (0: success).
type renewTURN struct {
	answers []int
	reqs    []*stun.Message
}

func (f *renewTURN) PerformTransactionWithContext(msg *stun.Message, _ net.Addr, _ bool, _ context.Context) (turnResult, error) {
	f.reqs = append(f.reqs, msg)
	if len(f.answers) == 0 {
		return nil, errors.New("timeout")
	}
	code := f.answers[0]
	f.answers = f.answers[1:]
	cls := stun.ClassErrorResponse
	if code == 0 {
		cls = stun.ClassSuccessResponse
	}
	setters := []stun.Setter{stun.NewTransactionIDSetter(msg.TransactionID), stun.NewType(msg.Type.Method, cls)}
	if code != 0 {
		setters = append(setters, stun.ErrorCodeAttribute{Code: stun.ErrorCode(code)})
	}
	if code == 401 || code == 438 {
		setters = append(setters, stun.NewRealm("vk"), stun.NewNonce("n"))
	}
	return stun.MustBuild(setters...), nil
}

func TestRenew(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 56000}
	// Refresh (challenged once), then the channel: the nonce learned for
	// the first request signs the second at once.
	f := &renewTURN{answers: []int{401, 0, 0}}
	if err := renew(context.Background(), f, &net.UDPAddr{}, "user", "pass", peer, 0x4001); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 3 || f.reqs[1].Type.Method != stun.MethodRefresh || f.reqs[2].Type.Method != stun.MethodChannelBind {
		t.Fatalf("requests %v", f.reqs)
	}
	if v, err := f.reqs[1].Get(stun.AttrLifetime); err != nil || len(v) != 4 || int(v[2])<<8|int(v[3]) != int(allocLifetime/time.Second) {
		t.Fatalf("lifetime %v, %v", v, err)
	}
	ch := f.reqs[2]
	if v, err := ch.Get(stun.AttrChannelNumber); err != nil || v[0] != 0x40 || v[1] != 0x01 {
		t.Fatalf("channel %v, %v", v, err)
	}
	var xp stun.XORMappedAddress
	if err := xp.GetFromAs(ch, stun.AttrXORPeerAddress); err != nil || !xp.IP.Equal(peer.IP) || xp.Port != peer.Port {
		t.Fatalf("peer %v, %v", xp, err)
	}
	if err := stun.NewLongTermIntegrity("user", "vk", "pass").Check(ch); err != nil {
		t.Fatal("channel bind not signed")
	}
	// Without a channel: a permission.
	f = &renewTURN{answers: []int{401, 0, 0}}
	if err := renew(context.Background(), f, &net.UDPAddr{}, "user", "pass", peer, 0); err != nil || f.reqs[2].Type.Method != stun.MethodCreatePermission {
		t.Fatalf("no permission: %v", err)
	}
	// An allocation VK no longer knows.
	f = &renewTURN{answers: []int{401, 437}}
	if err := renew(context.Background(), f, &net.UDPAddr{}, "user", "pass", peer, 0); !errors.Is(err, ErrAllocGone) || len(f.reqs) != 2 {
		t.Fatalf("gone: %v after %d requests", err, len(f.reqs))
	}
}

func TestNoNetwork(t *testing.T) {
	for msg, want := range map[string]bool{
		"write udp4 0.0.0.0:50449->95.163.34.131:19302: sendto: network is unreachable": true,
		"sendto: machine is not on the network":                                         true,
		"wsasendto: A socket operation was attempted to an unreachable network.":        true,
		"turn: failed to retransmit transaction":                                        false,
	} {
		if NoNetwork(errors.New(msg)) != want {
			t.Fatalf("%q: want %v", msg, want)
		}
	}
}
