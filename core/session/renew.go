package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v4"
)

// A sleeping phone stops pion's TURN timers: they run on the monotonic
// clock, which stands still while the device is suspended, but VK expires
// a permission after 5 minutes and an allocation after its lifetime in
// real time. A phone dozing with the screen off is awake for a moment
// every half minute or so, so pion's refreshes (every 2 minutes of awake
// time) come an hour or more apart in real time: the routes die one after
// another and the engine rebuilds them all (the stats showed 28 rebuilds
// of every route in one night).
//
// So once the device has slept, the session renews its allocation and its
// permission (or channel) itself, on the first moment it is awake after
// renewAfter of real time.
const (
	renewAfter = 2 * time.Minute
	// renewSlept: of that time the device slept at least this much (it
	// was awake for less), so pion's timers lag. An awake device never
	// needs it: pion refreshes in time.
	renewSlept = 30 * time.Second
	// allocLifetime: the lifetime asked for (VK may grant less).
	allocLifetime = 10 * time.Minute
	renewTimeout  = 5 * time.Second
)

// monoBase: monotonic time is read as time.Since(monoBase).
var monoBase = time.Now()

func monoNow() int64 { return int64(time.Since(monoBase)) }

// renewState: when the TURN state was last renewed, in real (wall) and in
// monotonic time; the gap between the two is the time slept.
type renewState struct {
	wall, mono atomic.Int64
	busy       atomic.Bool
}

func (r *renewState) mark(wall, mono int64) {
	r.wall.Store(wall)
	r.mono.Store(mono)
}

// due: renewAfter of real time passed since the last renewal, renewSlept
// of it asleep.
func (r *renewState) due(wall, mono int64) bool {
	w := wall - r.wall.Load()
	return w >= int64(renewAfter) && w-(mono-r.mono.Load()) >= int64(renewSlept)
}

// ErrAllocGone: VK no longer knows the allocation (it expired while the
// device slept).
var ErrAllocGone = errors.New("TURN allocation expired")

// RenewTURN renews the route's TURN allocation and permission in the
// background when the device slept so long that pion's own refreshes are
// late (see above). A route whose allocation is gone already is closed, so
// that the engine replaces it at once. It returns true when it started.
func (s *Session) RenewTURN(now time.Time) bool {
	return s.renew.due(now.UnixNano(), monoNow()) && s.RenewNow()
}

// RenewNow renews the TURN state at once (the network came back after an
// outage, during which pion's refreshes failed).
func (s *Session) RenewNow() bool {
	if s.Closed() || s.tc == nil || s.turnPeer == nil || !s.renew.busy.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer s.renew.busy.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), renewTimeout)
		defer cancel()
		go func() {
			select {
			case <-s.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		err := renew(ctx, pionTransactor{s.tc}, s.turnAddr, s.turnUser, s.turnPass, s.turnPeer, s.channel())
		switch {
		case err == nil:
			s.renew.mark(time.Now().UnixNano(), monoNow())
		case s.Closed():
		case errors.Is(err, ErrAllocGone):
			s.logNote("route %d: TURN allocation on %s expired while the device slept, replacing it", s.ID, s.Server)
			s.Close()
		default:
			s.logNote("route %d: TURN renewal after sleep failed: %v", s.ID, err)
		}
	}()
	return true
}

func (s *Session) logNote(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

// channel is the channel pion bound to the peer (0: none, packets go in
// Send indications under a permission).
func (s *Session) channel() uint16 {
	c, ok := s.relay.(interface {
		FindChannelNumberByAddr(net.Addr) (uint16, bool)
	})
	if !ok {
		return 0
	}
	n, ok := c.FindChannelNumberByAddr(s.turnPeer)
	if !ok {
		return 0
	}
	return n
}

// renew refreshes the allocation, then the channel binding (which also
// refreshes the permission, RFC 5766 11.2) or else the permission.
func renew(ctx context.Context, t transactor, server net.Addr, user, pass string, peer *net.UDPAddr, channel uint16) error {
	a := &turnAuth{user: user, pass: pass}
	if err := a.ask(ctx, t, server, stun.MethodRefresh, lifetimeAttr(allocLifetime)); err != nil {
		var ce *codeError
		if errors.As(err, &ce) && ce.code == stun.CodeAllocMismatch {
			return ErrAllocGone
		}
		return err
	}
	xp := xorPeer{peer}
	if channel != 0 {
		return a.ask(ctx, t, server, stun.MethodChannelBind, channelAttr(channel), xp)
	}
	return a.ask(ctx, t, server, stun.MethodCreatePermission, xp)
}

// turnAuth signs requests with the long-term credentials; it learns the
// realm and nonce from the server's 401/438 answers and keeps them for
// the next request.
type turnAuth struct {
	user, pass string
	realm      stun.Realm
	nonce      stun.Nonce
}

// codeError: the server refused a request.
type codeError struct {
	method string
	code   stun.ErrorCode
	reason string
}

func (e *codeError) Error() string { return fmt.Sprintf("%s: %d %s", e.method, e.code, e.reason) }

func (a *turnAuth) ask(ctx context.Context, t transactor, server net.Addr, method stun.Method, attrs ...stun.Setter) error {
	name := strings.ToLower(method.String())
	for try := 0; try < 4; try++ {
		setters := append([]stun.Setter{stun.TransactionID, stun.NewType(method, stun.ClassRequest)}, attrs...)
		if a.nonce != nil {
			setters = append(setters, stun.NewUsername(a.user), a.realm, a.nonce, stun.NewLongTermIntegrity(a.user, a.realm.String(), a.pass))
		}
		setters = append(setters, stun.Fingerprint)
		msg, err := stun.Build(setters...)
		if err != nil {
			return err
		}
		res, err := t.PerformTransactionWithContext(msg, server, false, ctx)
		if err != nil {
			return err
		}
		if res.Type.Class == stun.ClassSuccessResponse {
			return nil
		}
		var code stun.ErrorCodeAttribute
		if err := code.GetFrom(res); err != nil {
			return fmt.Errorf("%s: answer without an error code", name)
		}
		switch code.Code {
		case stun.CodeUnauthorized, stun.CodeStaleNonce:
			if err := a.nonce.GetFrom(res); err != nil {
				return fmt.Errorf("%s: %d without a nonce", name, code.Code)
			}
			_ = a.realm.GetFrom(res) // a stale nonce answer may omit it
		default:
			return &codeError{name, code.Code, string(code.Reason)}
		}
	}
	return fmt.Errorf("%s: no nonce accepted", name)
}

// lifetimeAttr is the LIFETIME attribute (seconds).
type lifetimeAttr time.Duration

func (l lifetimeAttr) AddTo(m *stun.Message) error {
	v := uint32(time.Duration(l) / time.Second)
	m.Add(stun.AttrLifetime, []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	return nil
}

// channelAttr is the CHANNEL-NUMBER attribute.
type channelAttr uint16

func (c channelAttr) AddTo(m *stun.Message) error {
	m.Add(stun.AttrChannelNumber, []byte{byte(c >> 8), byte(c), 0, 0})
	return nil
}

// xorPeer is the XOR-PEER-ADDRESS attribute.
type xorPeer struct{ a *net.UDPAddr }

func (p xorPeer) AddTo(m *stun.Message) error {
	return stun.XORMappedAddress{IP: p.a.IP, Port: p.a.Port}.AddToAs(m, stun.AttrXORPeerAddress)
}
