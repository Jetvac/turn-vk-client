package session

import (
	"context"
	"errors"
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

// releaseTimeout: a phone on a slow mobile network may need several
// round trips of half a second each (401, then the request again).
const releaseTimeout = 5 * time.Second

var releasing sync.WaitGroup

// WaitReleased waits (at most d) until the allocations of closed sessions
// are freed; the engine calls it when it stops. It returns false if some
// were still being freed when d ran out.
func WaitReleased(d time.Duration) bool {
	c := make(chan struct{})
	go func() { releasing.Wait(); close(c) }()
	select {
	case <-c:
		return true
	case <-time.After(d):
		return false
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

// release frees the allocation on server (Refresh with lifetime 0),
// authenticating with the long-term credentials (turnAuth, renew.go).
func release(ctx context.Context, t transactor, server net.Addr, user, pass string) (releaseResult, error) {
	a := &turnAuth{user: user, pass: pass}
	err := a.ask(ctx, t, server, stun.MethodRefresh, lifetimeAttr(0))
	var ce *codeError
	switch {
	case err == nil:
		return released, nil
	case errors.As(err, &ce) && ce.code == stun.CodeAllocMismatch:
		return releaseGone, nil
	default:
		return releaseFailed, err
	}
}
