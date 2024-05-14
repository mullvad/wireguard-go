package device

type EventType uint32

// NOTE: discriminants must be kept in sync with `MaybenotEventType` in cmaybenot.h
const (
	NonpaddingSent     = EventType(0)
	NonpaddingReceived = EventType(1)
	PaddingSent        = EventType(2)
	PaddingReceived    = EventType(3)
)

// If the first byte of a packet is this, then it should be interpreted as a DAITA padding packet,
// instead of an IP packet.
const DaitaPaddingMarker uint8 = 0xff

// Length (in bytes) of the header of a DAITA padding packet.
const DaitaHeaderLen uint16 = 4

type Daita interface {
	Disable()
	NonpaddingSent(peer *Peer, packetLen uint)
	NonpaddingReceived(peer *Peer, packetLen uint)
	PaddingSent(peer *Peer, packetLen uint, machine_id uint64)
	PaddingReceived(peer *Peer, packetLen uint)
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
