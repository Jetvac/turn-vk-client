package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5"
)

// When a route closes, its TURN allocation must be freed: VK allows each
// set of credentials (and each guest) only so many at a time (error 486),
// and an allocation nobody frees stays counted until its lifetime runs
// out (minutes). pion's Close sends one Refresh with lifetime 0 and does
// not wait for the answer; when that is lost or refused (a stale nonce),
// VK keeps the allocation, and a quick restart of the app hits the limit
// and moves routes to a new VK guest, which may cost a captcha.
//
// So after pion's attempt the session sends its own Refresh(0) and waits
// for VK's answer, repeating it with a fresh nonce if asked.

const releaseTimeout = 2 * time.Second

var releasing sync.WaitGroup

// WaitReleased waits (at most d) until the allocations of closed sessions
// are freed; the engine calls it when it stops.
func WaitReleased(d time.Duration) {
	c := make(chan struct{})
	go func() { releasing.Wait(); close(c) }()
	select {
	case <-c:
	case <-time.After(d):
	}
}

// releaseResult: what VK answered, for the log and tests.
type releaseResult int

const (
	released       releaseResult = iota
	releaseGone                  // 437: no such allocation (pion's request got through)
	releaseFailed                // no answer or an error
	releaseSkipped               // never allocated
)

type transactor interface {
	PerformTransactionWithContext(msg *stun.Message, to net.Addr, ignoreResult bool, ctx context.Context) (turnResult, error)
}

// turnResult is the part of pion's TransactionResult release needs.
type turnResult = *stun.Message

// pionTransactor adapts *turn.Client.
type pionTransactor struct{ c *turn.Client }

func (p pionTransactor) PerformTransactionWithContext(msg *stun.Message, to net.Addr, ignore bool, ctx context.Context) (turnResult, error) {
	res, err := p.c.PerformTransactionWithContext(msg, to, ignore, ctx)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// lifetimeZero is the LIFETIME attribute set to 0: free the allocation.
type lifetimeZero struct{}

func (lifetimeZero) AddTo(m *stun.Message) error {
	m.Add(stun.AttrLifetime, []byte{0, 0, 0, 0})
	return nil
}

// release frees the allocation on server, authenticating with the
// long-term credentials; it learns the realm and nonce from the server's
// 401/438 answers.
func release(ctx context.Context, t transactor, server net.Addr, user, pass string) (releaseResult, error) {
	var realm stun.Realm
	var nonce stun.Nonce
	for try := 0; try < 4; try++ {
		setters := []stun.Setter{stun.TransactionID, stun.NewType(stun.MethodRefresh, stun.ClassRequest), lifetimeZero{}}
		if nonce != nil {
			setters = append(setters, stun.NewUsername(user), realm, nonce, stun.NewLongTermIntegrity(user, realm.String(), pass))
		}
		setters = append(setters, stun.Fingerprint)
		msg, err := stun.Build(setters...)
		if err != nil {
			return releaseFailed, err
		}
		res, err := t.PerformTransactionWithContext(msg, server, false, ctx)
		if err != nil {
			return releaseFailed, err
		}
		if res.Type.Class == stun.ClassSuccessResponse {
			return released, nil
		}
		var code stun.ErrorCodeAttribute
		if err := code.GetFrom(res); err != nil {
			return releaseFailed, fmt.Errorf("refresh: answer without an error code")
		}
		switch code.Code {
		case stun.CodeUnauthorized, stun.CodeStaleNonce:
			if err := nonce.GetFrom(res); err != nil {
				return releaseFailed, fmt.Errorf("refresh: %d without a nonce", code.Code)
			}
			_ = realm.GetFrom(res) // a stale nonce answer may omit it
		case stun.CodeAllocMismatch:
			return releaseGone, nil
		default:
			return releaseFailed, fmt.Errorf("refresh: %d %s", code.Code, code.Reason)
		}
	}
	return releaseFailed, errors.New("refresh: no nonce accepted")
}
