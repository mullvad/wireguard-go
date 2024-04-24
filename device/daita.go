package device

import (
	"fmt"
	"time"
	"unsafe"
)

// #include <stdio.h>
// #include <stdlib.h>
// #include "../cmaybenot/cmaybenot.h"
// #cgo LDFLAGS: -L${SRCDIR}/../cmaybenot/target/release -l:libcmaybenot.a -lm
import "C"

type Daita struct {
	Events         chan *Event
	actions        chan *Action
	maybenot       *C.Maybenot
	newActionsBuf  []C.MaybenotAction
	machineActions map[uint64]Action
	logger         *Logger
}

type EventType uint32

const (
	NonpaddingSent = EventType(iota)
	NonpaddingReceived
	PaddingSent
	PaddingReceived
)

type Event struct {
	// The machine that generated the action that generated this event, if any.
	Machine uint64

	Peer      NoisePublicKey
	EventType EventType
	XmitBytes uint16
}

type ActionType uint32

const (
	Cancel        = 0
	InjectPadding = 1
	BlockOutgoing = 2
)

const (
	ERROR_GENERAL_FAILURE      = -1
	ERROR_INTERMITTENT_FAILURE = -2
)

type EventContext struct {
	tunnelHandle int32
	peer         NoisePublicKey
}

type Action struct {
	Peer NoisePublicKey

	ActionType ActionType

	// The maybenot machine that generated the action.
	// Should be propagated back by events generated by this action.
	Machine uint64

	// The time at which the action should be performed
	Time time.Time

	// TODO: Support more action types than InjectPadding
	Payload Padding
}

type Padding struct {
	ByteCount uint16
	Replace   bool
}

// TODO: Turn off DAITA? Remember to send a nil action when doing so
func (device *Device) ActivateDaita(machines string, eventsCapacity uint, actionsCapacity uint) bool {
	if device.Daita != nil {
		device.log.Errorf("Failed to activate DAITA as it is already active")
		return false
	}

	device.log.Verbosef("DAITA activated")
	device.log.Verbosef("Params: eventsCapacity=%v, actionsCapacity=%v", eventsCapacity, actionsCapacity) // TODO: Deleteme

	var maybenot *C.Maybenot
	c_machines := C.CString(machines)
	maybenot_result := C.maybenot_start(
		(*C.int8_t)(c_machines), 0.0, 0.0, 1440,
		&maybenot,
	)
	C.free(unsafe.Pointer(c_machines))

	if maybenot_result != 0 {
		device.log.Errorf("Failed to initialize maybenot, code=%d", maybenot_result)
		return false
	}

	numMachines := C.maybenot_num_machines(maybenot)
	daita := Daita{
		Events:         make(chan *Event, eventsCapacity),
		actions:        make(chan *Action, actionsCapacity),
		maybenot:       maybenot,
		newActionsBuf:  make([]C.MaybenotAction, numMachines),
		machineActions: map[uint64]Action{},
	}

	go device.HandleDaitaActions()
	go daita.handleEvents()
	device.Daita = &daita

	return true
}

func newDaita(eventsCapacity uint, actionsCapacity uint) *Daita {
	daita := new(Daita)
	// TODO: Remove this comment
	// Not specifying a buffer size means that sending to a non-empty channel
	// is blocking: https://go.dev/doc/effective_go#channels
	daita.Events = make(chan *Event, eventsCapacity)
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
	case daita.Events <- &event:
	default:
		peer.device.log.Verbosef("Dropped DAITA event %v due to full buffer", event.EventType)
	}
}

func (daita *Daita) Close() {
	// *if* Daita has not yet been initialized before calling Daita.Close,
	// daita will be nil.
	if daita == nil {
		return
	}
	daita.actions <- nil
	daita.Events <- nil
}

// TODO: send nil event if closing DAITA
func (daita *Daita) ReceiveEvent() *Event {
	return <-daita.Events
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
		if action.ActionType != 1 {
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

func (daita *Daita) handleEvents() {

	// if self == nil {
	// 	self.logger.Errorf("DAITA not activated")
	// 	return
	// }

	// TODO: proper race-condition safe nil checks for everything
	events := daita.Events

	// create a new inactive timer to help us track when maybenot actions should be performed.
	actionTimer := time.NewTimer(time.Duration(999999999999999999)) // wtf
	actionTimer.Stop()

	for {
		now := time.Now()

		// get the time until the next action from machineActions should be performed, if any
		var nextActionMachine *uint64 = nil
		var nextActionIn time.Duration
		for machine, action := range daita.machineActions {
			timeUntilAction := action.Time.Sub(now)

			if nextActionMachine == nil || timeUntilAction < nextActionIn {
				nextActionIn = timeUntilAction
				nextActionMachine = &machine
			}
		}

		// if we found a pending action, set the timer
		if nextActionMachine != nil {
			actionTimer.Reset(nextActionIn)
		}

		// wait until we either get a new event, or until an action is supposed to fire
		select {
		case event := <-events:
			// make sure the timer is stopped and cleared
			if nextActionMachine != nil && !actionTimer.Stop() {
				<-actionTimer.C
			}

			if event == nil {
				daita.logger.Errorf("No more DAITA events")
				C.maybenot_stop(daita.maybenot)
				return
			}

			daita.handleEvent(*event)

		case <-actionTimer.C:
			// it's time to do the action! pop it from the map and send it to wireguard-go
			action := daita.machineActions[*nextActionMachine]
			delete(daita.machineActions, *nextActionMachine)
			daita.actOnAction(action)
		}
	}
}

func (daita *Daita) handleEvent(event Event) {
	cEvent := C.MaybenotEvent{
		machine:    C.uint64_t(event.Machine),
		event_type: C.uint32_t(event.EventType),
		xmit_bytes: C.uint16_t(event.XmitBytes),
	}

	var actionsWritten C.uint64_t

	// TODO: is it even sound to pass a slice reference like this?
	// TODO: handle error
	C.maybenot_on_event(daita.maybenot, cEvent, &daita.newActionsBuf[0], &actionsWritten)

	// TODO: there is a small disparity here, between the time used by maybenot_on_event,
	// and `now`. Is this a problem?
	now := time.Now()

	newActions := daita.newActionsBuf[0:actionsWritten]
	for _, newAction := range newActions {
		// TODO: support more actions
		if newAction.tag != 1 /* INJECT_PADDING */ {
			daita.logger.Errorf("ignoring action type %d, unimplemented", newAction.tag)
			continue
		}

		newActionGo := daita.maybenotActionToGo(newAction, now, event.Peer)
		machine := newActionGo.Machine
		daita.machineActions[machine] = newActionGo
	}
}

func (daita *Daita) maybenotActionToGo(action_c C.MaybenotAction, now time.Time, peer NoisePublicKey) Action {
	// TODO: support more actions
	if action_c.tag != 1 /* INJECT_PADDING */ {
		panic("Unsupported tag")
	}

	// cast union to the ActionInjectPadding variant
	padding_action := (*C.MaybenotAction_InjectPadding_Body)(unsafe.Pointer(&action_c.anon0[0]))

	timeout := maybenotDurationToGoDuration(padding_action.timeout)

	return Action{
		Peer:       peer,
		Machine:    uint64(padding_action.machine),
		Time:       now.Add(timeout),
		ActionType: 1, // TODO
		Payload: Padding{
			ByteCount: uint16(padding_action.size),
			Replace:   bool(padding_action.replace),
		},
	}
}

func maybenotDurationToGoDuration(duration C.MaybenotDuration) time.Duration {
	// let's just assume this is fine...
	nanoseconds := uint64(duration.secs)*1_000_000_000 + uint64(duration.nanos)
	return time.Duration(nanoseconds)
}

func (daita *Daita) actOnAction(action Action) {
	err := daita.SendAction(action)
	if err != nil {
		daita.logger.Errorf("Failed to send DAITA action %v because of %v", action, err)
		return
	}
}
