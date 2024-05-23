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
	events        chan Event
	actions       chan Action
	maybenot      *C.Maybenot
	newActionsBuf []C.MaybenotAction
	paddingQueue  map[uint64]*time.Timer // Map from machine to queued padding packets
	logger        *Logger
	stopping      sync.WaitGroup // waitgroup for handleEvents and HandleDaitaActions
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
	Timeout time.Duration

	// TODO: Support more action types than ActionTypeInjectPadding
	Payload Padding
}

type Padding struct {
	// The size of the padding packet, in bytes. NOT including the Daita header.
	ByteCount uint16
	Replace   bool
}

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

	mtu, err := peer.device.tun.device.MTU()
	if err != nil {
		peer.device.log.Errorf("Failed to activate DAITA as because of error fetching MTU, %v", err)
		return false
	}
	peer.device.log.Verbosef("MTU %v", mtu)
	var maybenot *C.Maybenot
	c_machines := C.CString(machines)
	maxPaddingBytes := C.double(0.0)  // TODO: set from args
	maxBlockingBytes := C.double(0.0) // TODO: set from args
	maybenot_result := C.maybenot_start(
		c_machines, maxPaddingBytes, maxBlockingBytes, C.ushort(mtu),
		&maybenot,
	)
	C.free(unsafe.Pointer(c_machines))

	if maybenot_result != 0 {
		peer.device.log.Errorf("Failed to initialize maybenot, code=%d", maybenot_result)
		return false
	}

	numMachines := C.maybenot_num_machines(maybenot)
	daita := MaybenotDaita{
		events:        make(chan Event, eventsCapacity),
		maybenot:      maybenot,
		newActionsBuf: make([]C.MaybenotAction, numMachines),
		paddingQueue:  map[uint64]*time.Timer{},
		logger:        peer.device.log,
	}

	daita.stopping.Add(1)
	go daita.handleEvents(peer)
	peer.daita = &daita

	return true
}

// Stop the MaybenotDaita instance. It must not be used after calling this.
func (daita *MaybenotDaita) Close() {
	daita.logger.Verbosef("Waiting for DAITA routines to stop")
	close(daita.events)
	for _, queuedPadding := range daita.paddingQueue {
		if queuedPadding.Stop() {
			daita.stopping.Done()
		}
	}
	daita.stopping.Wait()
	daita.logger.Verbosef("DAITA routines have stopped")
}

func (daita *MaybenotDaita) NonpaddingReceived(peer *Peer, packetLen uint) {
	daita.event(peer, NonpaddingReceived, packetLen, 0)
}

func (daita *MaybenotDaita) PaddingReceived(peer *Peer, packetLen uint) {
	daita.event(peer, PaddingReceived, packetLen, 0)
}

func (daita *MaybenotDaita) PaddingSent(peer *Peer, packetLen uint, machine uint64) {
	daita.event(peer, PaddingSent, packetLen, machine)
}

func (daita *MaybenotDaita) NonpaddingSent(peer *Peer, packetLen uint) {
	daita.event(peer, NonpaddingSent, packetLen, 0)
}

func (daita *MaybenotDaita) event(peer *Peer, eventType EventType, packetLen uint, machine uint64) {
	if daita == nil {
		return
	}

	event := Event{
		Machine:   machine,
		Peer:      peer.handshake.remoteStatic,
		EventType: eventType,
		XmitBytes: uint16(packetLen),
	}

	// TODO: stringify Event?
	// Too verbose, we have to skip this
	// peer.device.log.Verbosef("DAITA event: %v len=%d", eventType, packetLen)

	select {
	case daita.events <- event:
	default:
		peer.device.log.Verbosef("Dropped DAITA event %v due to full buffer", event.EventType)
	}
}

func injectPadding(action Action, peer *Peer) {
	if action.ActionType != ActionTypeInjectPadding {
		peer.device.log.Errorf("Got unknown action type %v", action.ActionType)
		return
	}

	elem := peer.device.NewOutboundElement()

	elem.padding = true
	elem.machine_id = &action.Machine

	var size uint16
	if peer.constantPacketSize {
		sizeInt, err := peer.device.tun.device.MTU()
		if err != nil {
			peer.device.log.Errorf("Failed to inject DAITA padding because of missing MTU: %v", err)
			return
		}
		size = uint16(sizeInt)
	} else {
		size = action.Payload.ByteCount
	}
	if size == 0 {
		peer.device.log.Errorf("DAITA padding action contained invalid size %v bytes", size)
		return
	}

	elem.packet = elem.buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+int(size)]
	elem.packet[0] = DaitaPaddingMarker
	daitaLengthField := binary.BigEndian.AppendUint16([]byte{}, size)
	copy(elem.packet[DaitaOffsetTotalLength:DaitaOffsetTotalLength+2], daitaLengthField)

	peer.StagePacket(elem)
}

func (daita *MaybenotDaita) handleEvents(peer *Peer) {
	defer func() {
		C.maybenot_stop(daita.maybenot)
		daita.stopping.Done()
		daita.logger.Verbosef("%v - DAITA: event handler - stopped", peer)
	}()

	for {
		event, more := <-daita.events
		if !more {
			return
		}

		daita.handleEvent(event, peer)
	}
}

func (daita *MaybenotDaita) handleEvent(event Event, peer *Peer) {

	for _, cAction := range daita.maybenotEventToActions(event) {
		action := cActionToGo(cAction)

		switch action.ActionType {
		case ActionTypeCancel:
			machine := action.Machine
			// If padding is queued for the machine, cancel it
			if queuedPadding, ok := daita.paddingQueue[machine]; ok {
				if queuedPadding.Stop() {
					daita.stopping.Done()
				}
			}
		case ActionTypeInjectPadding:
			// Check if a padding packet was already queued for the machine
			// If so, try to cancel it
			timer, paddingWasQueued := daita.paddingQueue[action.Machine]
			// If no padding was queued, or the action fire before we manage to
			// cancel it, we need to increment the wait group again
			if !paddingWasQueued || !timer.Stop() {
				daita.stopping.Add(1)
			}

			daita.paddingQueue[action.Machine] =
				time.AfterFunc(action.Timeout, func() {
					defer daita.stopping.Done()
					injectPadding(action, peer)
				})
		case ActionTypeBlockOutgoing:
			daita.logger.Errorf("ignoring action type ActionTypeBlockOutgoing, unimplemented")
			continue
		}
	}
}

func (daita *MaybenotDaita) maybenotEventToActions(event Event) []C.MaybenotAction {
	cEvent := C.MaybenotEvent{
		machine:    C.uint64_t(event.Machine),
		event_type: C.uint32_t(event.EventType),
		xmit_bytes: C.uint16_t(event.XmitBytes),
	}

	var actionsWritten C.uint64_t

	// TODO: use unsafe.SliceData instead of the pointer dereference when the Go version gets bumped to 1.20 or later
	// TODO: fetch an error string from the FFI corresponding to the error code
	result := C.maybenot_on_event(daita.maybenot, cEvent, &daita.newActionsBuf[0], &actionsWritten)
	if result != 0 {
		daita.logger.Errorf("Failed to handle event as it was a null pointer\nEvent: %d\n", event)
		return nil
	}

	newActions := daita.newActionsBuf[:actionsWritten]
	return newActions
}

func cActionToGo(action_c C.MaybenotAction) Action {
	// TODO: support more actions
	if action_c.tag != C.MaybenotAction_InjectPadding {
		panic("Unsupported tag")
	}

	// cast union to the ActionInjectPadding variant
	padding_action := (*C.MaybenotAction_InjectPadding_Body)(unsafe.Pointer(&action_c.anon0[0]))

	timeout := maybenotDurationToGoDuration(padding_action.timeout)

	return Action{
		Machine:    uint64(padding_action.machine),
		Timeout:    timeout,
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
