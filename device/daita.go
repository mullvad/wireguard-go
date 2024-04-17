package device

import (
	"fmt"
)

type Daita struct {
	events  chan Event
	actions chan *Action
}

type EventType uint32

const (
	NonpaddingSent = EventType(iota)
	NonpaddingReceived
	PaddingSent
	PaddingReceived
)

type Event struct {
	Peer      NoisePublicKey
	EventType EventType
	XmitBytes uint16
	//TODO? context uint64
}

type ActionType uint32

const (
	InjectPadding = ActionType(iota)
)

type Action struct {
	Peer       NoisePublicKey
	ActionType ActionType
	// TODO: I assume Payload is somehow dependent on `actionType`?
	// Maybe the `ActionType` enum could be replaced with an interface,
	// and `actionType` + `Payload` squashed into one member field.
	// In any case, the `Padding` type is not general enough as it
	// corresponds to the `InjectPadding` variant.
	Payload Padding
	//TODO? context uint64
}

type Padding struct {
	ByteCount uint16
	Replace   bool
}

// TODO: Turn off DAITA? Remember to send a nil action when doing so
func (device *Device) ActivateDaita(eventsCapacity uint, actionsCapacity uint) bool {
	if device.Daita != nil {
		device.log.Errorf("Failed to activate DAITA as it is already active")
		return false
	}
	device.Daita = newDaita(eventsCapacity, actionsCapacity)
	go device.HandleDaitaActions()

	device.log.Verbosef("DAITA activated")
	device.log.Verbosef("Params: eventsCapacity=%v, actionsCapacity=%v", eventsCapacity, actionsCapacity) // TODO: Deleteme
	fmt.Println("DAITA activated stdout")                                                                 // TODO: deleteme
	return true
}

func newDaita(eventsCapacity uint, actionsCapacity uint) *Daita {
	daita := new(Daita)
	// TODO: Remove this comment
	// Not specifying a buffer size means that sending to a non-empty channel
	// is blocking: https://go.dev/doc/effective_go#channels
	daita.events = make(chan Event, eventsCapacity)
	daita.actions = make(chan *Action, actionsCapacity)
	return daita
}

func (daita *Daita) NonpaddingReceived(peer *Peer, packet []byte) {
	daita.sendEvent(peer, packet, NonpaddingReceived)
}

func (daita *Daita) PaddingReceived(peer *Peer, packet []byte) {
	daita.sendEvent(peer, packet, PaddingReceived)
}

func (daita *Daita) NonpaddingSent(peer *Peer, packet []byte) {
	daita.sendEvent(peer, packet, NonpaddingSent)
}

func (daita *Daita) PaddingSent(peer *Peer, packet []byte) {
	daita.sendEvent(peer, packet, PaddingSent)
}

// TODO: change packet to packet_len?
func (daita *Daita) sendEvent(peer *Peer, packet []byte, eventType EventType) {
	event := Event{
		// TODO: am i really copying the array?
		Peer:      peer.handshake.remoteStatic,
		EventType: eventType,
		XmitBytes: uint16(len(packet)),
	}

	peer.device.log.Verbosef("DAITA event: %v len=%d", eventType, len(packet))

	select {
	case daita.events <- event:
	default:
		peer.device.log.Verbosef("Dropped DAITA event %v due to full buffer", event.EventType)
	}
}

// TODO: send nil event if closing DAITA
func (daita *Daita) ReceiveEvent() (Event, error) {
	return <-daita.events, nil
}

func (daita *Daita) SendAction(action Action) error {
	// if action == nil {
	// 	return errors.New("DAITA action was nil")
	// }
	fmt.Printf("Got DAITA action: %v\n", action)
	daita.actions <- &action
	return nil
}

// TODO: PaddingSent
// TODO: PaddingReceived

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
