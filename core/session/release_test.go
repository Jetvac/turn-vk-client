package session

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pion/stun/v4"
)

// fakeTURN answers Refresh requests from a script of error codes (0:
// success) and checks what each request carries.
type fakeTURN struct {
	t       *testing.T
	answers []int
	reqs    []*stun.Message
}

func (f *fakeTURN) PerformTransactionWithContext(msg *stun.Message, _ net.Addr, _ bool, _ context.Context) (turnResult, error) {
	f.reqs = append(f.reqs, msg)
	if msg.Type != stun.NewType(stun.MethodRefresh, stun.ClassRequest) {
		f.t.Fatalf("request type %v", msg.Type)
	}
	if v, err := msg.Get(stun.AttrLifetime); err != nil || len(v) != 4 || v[0]|v[1]|v[2]|v[3] != 0 {
		f.t.Fatalf("lifetime %v, %v", v, err)
	}
	if len(f.answers) == 0 {
		return nil, errors.New("timeout")
	}
	code := f.answers[0]
	f.answers = f.answers[1:]
	cls := stun.ClassErrorResponse
	if code == 0 {
		cls = stun.ClassSuccessResponse
	}
	setters := []stun.Setter{stun.NewTransactionIDSetter(msg.TransactionID), stun.NewType(stun.MethodRefresh, cls)}
	if code != 0 {
		setters = append(setters, stun.ErrorCodeAttribute{Code: stun.ErrorCode(code)})
	}
	if code == 401 || code == 438 {
		setters = append(setters, stun.NewRealm("vk"), stun.NewNonce("n"+string(rune('0'+len(f.reqs)))))
	}
	return stun.MustBuild(setters...), nil
}

func TestRelease(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []int
		want    releaseResult
		reqs    int
	}{
		{"challenge, then freed", []int{401, 0}, released, 2},
		{"stale nonce", []int{401, 438, 0}, released, 3},
		{"already freed by pion", []int{401, 437}, releaseGone, 2},
		{"refused", []int{401, 403}, releaseFailed, 2},
		{"no answer", nil, releaseFailed, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeTURN{t: t, answers: tc.answers}
			got, err := release(context.Background(), f, &net.UDPAddr{}, "user", "pass")
			if got != tc.want || len(f.reqs) != tc.reqs {
				t.Fatalf("got %v after %d requests (err %v), want %v after %d", got, len(f.reqs), err, tc.want, tc.reqs)
			}
			if (err != nil) != (tc.want == releaseFailed) {
				t.Fatalf("err = %v", err)
			}
			// After the challenge every request is signed for the realm
			// and with the latest nonce.
			for i, m := range f.reqs[1:] {
				var u stun.Username
				var n stun.Nonce
				if u.GetFrom(m) != nil || u.String() != "user" || n.GetFrom(m) != nil {
					t.Fatalf("request %d not authenticated", i+2)
				}
				if want := "n" + string(rune('0'+i+1)); n.String() != want {
					t.Fatalf("request %d nonce %q, want %q", i+2, n, want)
				}
				if err := stun.NewLongTermIntegrity("user", "vk", "pass").Check(m); err != nil {
					t.Fatalf("request %d integrity: %v", i+2, err)
				}
			}
		})
	}
}
