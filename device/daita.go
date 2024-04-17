package device

import (
	"fmt"
)

type Daita struct {
	events  chan *Event
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
	daita.events = make(chan *Event, eventsCapacity)
	daita.actions = make(chan *Action, actionsCapacity)
	return daita
}

func (daita *Daita) NonpaddingReceived(peer *Peer, packet_len int) {
	daita.sendEvent(peer, packet_len, NonpaddingReceived)
}

func (daita *Daita) PaddingReceived(peer *Peer, packet_len int) {
	daita.sendEvent(peer, packet_len, PaddingReceived)
}

func (daita *Daita) NonpaddingSent(peer *Peer, packet_len int) {
	daita.sendEvent(peer, packet_len, NonpaddingSent)
}

func (daita *Daita) PaddingSent(peer *Peer, packet_len int) {
	daita.sendEvent(peer, packet_len, PaddingSent)
}

// TODO: change packet to packet_len?
func (daita *Daita) sendEvent(peer *Peer, packet_len int, eventType EventType) {
	event := Event{
		// TODO: am i really copying the array?
		Peer:      peer.handshake.remoteStatic,
		EventType: eventType,
		XmitBytes: uint16(packet_len),
	}

	peer.device.log.Verbosef("DAITA event: %v len=%d", eventType, packet_len)

	select {
	case daita.events <- &event:
	default:
		peer.device.log.Verbosef("Dropped DAITA event %v due to full buffer", event.EventType)
	}
}

func (daita *Daita) Close() {
	daita.actions <- nil
	daita.events <- nil
}

// TODO: send nil event if closing DAITA
func (daita *Daita) ReceiveEvent() *Event {
	return <-daita.events
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

func (device *Device) HandleDaitaActions() {
	for action := range device.Daita.actions {
		if action == nil {
			device.log.Verbosef("Closing action channel")
			return
		}
		if action.ActionType != 0 {
			device.log.Errorf("Got unknown action type %v", action.ActionType)
		}

		elem := device.NewOutboundElement()

		elem.padding = true

		offset := MessageTransportHeaderSize
		size := int(action.Payload.ByteCount)

		if size == 0 || size > MaxContentSize {
			device.log.Errorf("DAITA padding action contained invalid size %v bytes", size)
			continue
		}

		elem.packet = elem.buffer[offset : offset+size]
		elem.packet[0] = 0xff
		// TODO: write elem.packet[2:3] = size

		peer := device.LookupPeer(action.Peer)
		if peer == nil {
			// TODO: Is this a proper way to handle invalid peers?
			device.log.Errorf("Closing action channel because of invalid peer")
			return
		}

		// TODO: fill elem
		peer.StagePacket(elem)

	}
}
