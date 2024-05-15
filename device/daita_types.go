package device

type EventType uint32

// NOTE: discriminants must be kept in sync with `MaybenotEventType` in cmaybenot.h
const (
	NonpaddingSent     = EventType(0)
	NonpaddingReceived = EventType(1)
	PaddingSent        = EventType(2)
	PaddingReceived    = EventType(3)
)

const (
	// Length (in bytes) of the header of a DAITA padding packet.
	DaitaHeaderLen uint16 = 4

	// The first byte of the header, taking the place of the IP version field, is the DAITA marker.
	// This is used to differentiate DAITA padding packets from IP packets.
	DaitaPaddingMarker uint8 = 0xff

	// Offset (in bytes) before the 16 bit packet length field in the DAITA header
	DaitaOffsetTotalLength uint16 = 2
)

type Daita interface {
	Close()
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
