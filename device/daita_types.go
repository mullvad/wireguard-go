package device

type EventType uint32

const (
	// NOTE: must be kept in sync with cmaybenot.h
	NonpaddingSent     = EventType(0)
	NonpaddingReceived = EventType(1)
	PaddingSent        = EventType(2)
	PaddingReceived    = EventType(3)
)

// If the first byte of a packet is this, then it should be interpreted as a DAITA padding packet,
// instead of an IP packet.
const DaitaPaddingMarker uint8 = 0xff

type Daita interface {
	Disable()
	Event(peer *Peer, eventType EventType, packetLen uint)
}

func (event EventType) String() string {
	var pretty string
	switch event {
	case NonpaddingSent:
		pretty = "NonpaddingSent"
	case NonpaddingReceived:
		pretty = "NonpaddingReceived"
	case PaddingSent:
		pretty = "PaddingSent"
	case PaddingReceived:
		pretty = "PaddingReceived"
	}
	return pretty
}
