//go:build daita
// +build daita

package device

import (
	"encoding/binary"
	"sync"
	"time"
	"unsafe"
)

// #include <stdio.h>
// #include <stdlib.h>
// #include "../cmaybenot/cmaybenot.h"
// #cgo LDFLAGS: -L${SRCDIR}/../cmaybenot/target/release -l:libcmaybenot.a -lm
import "C"

type MaybenotDaita struct {
	events         chan Event
	actions        chan Action
	maybenot       *C.Maybenot
	newActionsBuf  []C.MaybenotAction
	machineActions map[uint64]Action
	logger         *Logger
	stopping       sync.WaitGroup // waitgroup for handleEvents and HandleDaitaActions
}

type Event struct {
	// The machine that generated the action that generated this event, if any.
	Machine uint64

	Peer      NoisePublicKey
	EventType EventType
	XmitBytes uint16
}

type ActionType uint32

const (
	ActionTypeCancel ActionType = iota
	ActionTypeInjectPadding
	ActionTypeBlockOutgoing
)

const (
	ERROR_GENERAL_FAILURE      = -1
	ERROR_INTERMITTENT_FAILURE = -2
)

type Action struct {
	ActionType ActionType

	// The maybenot machine that generated the action.
	// Should be propagated back by events generated by this action.
	Machine uint64

	// The time at which the action should be performed
	Time time.Time

	// TODO: Support more action types than ActionTypeInjectPadding
	Payload Padding
}

type Padding struct {
	// The size of the padding packet, in bytes. NOT including the Daita header.
	ByteCount uint16
	Replace   bool
}

// TODO: Turn off DAITA? Remember to send a nil action when doing so
func (peer *Peer) EnableDaita(machines string, eventsCapacity uint, actionsCapacity uint) bool {
	peer.Lock()
	defer peer.Unlock()

	if !peer.isRunning.Load() {
		return false
	}

	if peer.daita != nil {
		peer.device.log.Errorf("Failed to activate DAITA as it is already active")
		return false
	}

	peer.device.log.Verbosef("Enabling DAITA for peer: %v", peer)
	peer.device.log.Verbosef("Params: eventsCapacity=%v, actionsCapacity=%v", eventsCapacity, actionsCapacity) // TODO: Deleteme

	var maybenot *C.Maybenot
	c_machines := C.CString(machines)
	maybenot_result := C.maybenot_start(
		(*C.int8_t)(c_machines), 0.0, 0.0, 1440,
		&maybenot,
	)
	C.free(unsafe.Pointer(c_machines))

	if maybenot_result != 0 {
		peer.device.log.Errorf("Failed to initialize maybenot, code=%d", maybenot_result)
		return false
	}

	numMachines := C.maybenot_num_machines(maybenot)
	daita := MaybenotDaita{
		events:         make(chan Event, eventsCapacity),
		actions:        make(chan Action, actionsCapacity),
		maybenot:       maybenot,
		newActionsBuf:  make([]C.MaybenotAction, numMachines),
		machineActions: map[uint64]Action{},
		logger:         peer.device.log,
	}

	daita.stopping.Add(2)
	go daita.HandleDaitaActions(peer)
	go daita.handleEvents(peer)
	peer.daita = &daita

	return true
}

// Stop the MaybenotDaita instance. It must not be used after calling this.
func (daita *MaybenotDaita) Disable() {
	daita.logger.Verbosef("Wating for DAITA routines to stop")
	close(daita.events)
	daita.stopping.Wait()
	daita.logger.Verbosef("DAITA routines have stopped")
}

func (daita *MaybenotDaita) Event(peer *Peer, eventType EventType, packetLen uint) {
	if daita == nil {
		return
	}

	event := Event{
		// TODO: am i really copying the array?
		Peer:      peer.handshake.remoteStatic,
		EventType: eventType,
		XmitBytes: uint16(packetLen),
	}

	peer.device.log.Verbosef("DAITA event: %v len=%d", eventType, packetLen)

	select {
	case daita.events <- event:
	default:
		peer.device.log.Verbosef("Dropped DAITA event %v due to full buffer", event.EventType)
	}
}

func (daita *MaybenotDaita) HandleDaitaActions(peer *Peer) {
	defer func() {
		daita.logger.Verbosef("%v - DAITA: action handler - stopped", peer)
		daita.stopping.Done()
	}()

	if peer == nil {
		return
	}

	for action := range daita.actions {
		if action.ActionType != ActionTypeInjectPadding {
			daita.logger.Errorf("Got unknown action type %v", action.ActionType)
			continue
		}

		elem := peer.device.NewOutboundElement()

		elem.padding = true

		offset := MessageTransportHeaderSize
		size := action.Payload.ByteCount + DaitaHeaderLen

		if size == 0 {
			peer.device.log.Errorf("DAITA padding action contained invalid size %v bytes", size)
			continue
		}

		// TODO: constants
		daitaLengthField := binary.BigEndian.AppendUint16([]byte{}, size)
		elem.packet = elem.buffer[offset : offset+int(size)]
		elem.packet[0] = 0xff
		elem.packet[2] = daitaLengthField[0]
		elem.packet[3] = daitaLengthField[1]

		// TODO: fill elem
		peer.StagePacket(elem)
	}
}

func (daita *MaybenotDaita) handleEvents(peer *Peer) {
	defer func() {
		close(daita.actions)
		C.maybenot_stop(daita.maybenot)
		daita.stopping.Done()
		daita.logger.Verbosef("%v - DAITA: event handler - stopped", peer)
	}()

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
		case event, more := <-daita.events:
			// make sure the timer is stopped and cleared
			if nextActionMachine != nil && !actionTimer.Stop() {
				<-actionTimer.C
			}

			if !more {
				return
			}

			daita.handleEvent(event)

		case <-actionTimer.C:
			// it's time to do the action! pop it from the map and send it to wireguard-go
			action := daita.machineActions[*nextActionMachine]
			delete(daita.machineActions, *nextActionMachine)
			daita.actions <- action
		}
	}
}

func (daita *MaybenotDaita) handleEvent(event Event) {
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

	newActions := daita.newActionsBuf[:actionsWritten]
	for _, newAction := range newActions {
		// TODO: support more actions
		if newAction.tag != C.MaybenotAction_InjectPadding {
			daita.logger.Errorf("ignoring action type %d, unimplemented", newAction.tag)
			continue
		}

		newActionGo := daita.maybenotActionToGo(newAction, now, event.Peer)
		machine := newActionGo.Machine
		daita.machineActions[machine] = newActionGo
	}
}

func (daita *MaybenotDaita) maybenotActionToGo(action_c C.MaybenotAction, now time.Time, peer NoisePublicKey) Action {
	// TODO: support more actions
	if action_c.tag != C.MaybenotAction_InjectPadding {
		panic("Unsupported tag")
	}

	// cast union to the ActionInjectPadding variant
	padding_action := (*C.MaybenotAction_InjectPadding_Body)(unsafe.Pointer(&action_c.anon0[0]))

	timeout := maybenotDurationToGoDuration(padding_action.timeout)

	return Action{
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
