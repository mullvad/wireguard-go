package device

type EventType uint32

// NOTE: discriminants must be kept in sync with `MaybenotEventType` in maybenot-ffi/maybenot.h
const (
	NormalRecv  = EventType(0)
	PaddingRecv = EventType(1)
	TunnelRecv  = EventType(2)

	NormalSent  = EventType(3)
	PaddingSent = EventType(4)
	TunnelSent  = EventType(5)

	BlockingBegin = EventType(6)
	BlockingEnd   = EventType(7)

	TimerBegin = EventType(8)
	TimerEnd   = EventType(9)
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
	NormalSent(peer *Peer, packetLen uint)
	NormalRecv(peer *Peer, packetLen uint)
	PaddingSent(peer *Peer, packetLen uint, machine_id uint64)
	PaddingRecv(peer *Peer, packetLen uint)
}

func (event EventType) String() string {
	var pretty string
	switch event {
	case NormalRecv:
		pretty = "NormalRecv"
	case PaddingRecv:
		pretty = "PaddingRecv"
	case TunnelRecv:
		pretty = "TunnelRecv"
	case NormalSent:
		pretty = "NormalSent"
	case PaddingSent:
		pretty = "PaddingSent"
	case TunnelSent:
		pretty = "TunnelSent"
	case BlockingBegin:
		pretty = "BlockingBegin"
	case BlockingEnd:
		pretty = "BlockingEnd"
	case TimerBegin:
		pretty = "TimerBegin"
	case TimerEnd:
		pretty = "TimerEnd"
	}
	return pretty
}
