package session

import (
	"encoding/binary"
	"errors"
)

// Statistics reports (TurnVK servers): the engine sends a compressed
// report on a path, the server acknowledges it by id.
//
//	STATS    0x49 | version | id (4) | zlib(JSON)
//	STATSACK 0x4A | version | id (4)
const (
	msgStats    = 0x49
	msgStatsAck = 0x4A

	// MaxStats is the most a report may take, compressed: one datagram
	// well under the tunnel's packets.
	MaxStats = 1000
)

// SendStats sends one report on the path.
func (s *Session) SendStats(id uint32, body []byte) error {
	if !s.direct {
		return errors.New("statistics need the direct protocol")
	}
	if len(body) > MaxStats {
		return errors.New("report too large")
	}
	b := make([]byte, 0, 6+len(body))
	b = append(b, msgStats, directVersion)
	b = binary.BigEndian.AppendUint32(b, id)
	b = append(b, body...)
	return s.sendDirect(b)
}
