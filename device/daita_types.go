package device

type EventType uint32

const (
	// NOTE: must be kept in sync with cmaybenot.h
	NonpaddingSent     = EventType(0)
	NonpaddingReceived = EventType(1)
	PaddingSent        = EventType(2)
	PaddingReceived    = EventType(3)
)

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
