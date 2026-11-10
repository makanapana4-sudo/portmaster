package kextinterface

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func makeInfoFrame(infoType byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = infoType
	binary.LittleEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func TestRecvInfoRejectsOversizedFrameBeforeReadingPayload(t *testing.T) {
	header := make([]byte, 5)
	header[0] = InfoLogLine
	binary.LittleEndian.PutUint32(header[1:], maxInfoPayloadSize+1)

	_, err := RecvInfo(bytes.NewReader(header))
	if !errors.Is(err, ErrInfoPayloadTooLarge) {
		t.Fatalf("expected ErrInfoPayloadTooLarge, got %v", err)
	}
}

func TestRecvInfoRejectsBandwidthCountThatCannotFitFrame(t *testing.T) {
	payload := make([]byte, 5)
	payload[0] = 6
	binary.LittleEndian.PutUint32(payload[1:], ^uint32(0))
	frame := makeInfoFrame(InfoBandwidthStatsV4, payload)

	_, err := RecvInfo(bytes.NewReader(frame))
	if !errors.Is(err, ErrUnexpectedInfoSize) {
		t.Fatalf("expected ErrUnexpectedInfoSize, got %v", err)
	}
}

func TestRecvInfoDoesNotReadPastMalformedFrame(t *testing.T) {
	malformed := makeInfoFrame(InfoConnectionEndEventV4, []byte{1})
	next := makeInfoFrame(InfoLogLine, []byte{3, 'o', 'k'})
	stream := bytes.NewReader(append(malformed, next...))

	_, err := RecvInfo(stream)
	if !errors.Is(err, ErrUnexpectedInfoSize) {
		t.Fatalf("expected ErrUnexpectedInfoSize, got %v", err)
	}

	info, err := RecvInfo(stream)
	if err != nil {
		t.Fatalf("failed to parse frame after malformed frame: %v", err)
	}
	if info.LogLine == nil || info.LogLine.Severity != 3 || info.LogLine.Line != "ok" {
		t.Fatalf("unexpected following frame: %+v", info)
	}
}

func TestRecvInfoAcceptsEmptyLogMessage(t *testing.T) {
	frame := makeInfoFrame(InfoLogLine, []byte{2})

	info, err := RecvInfo(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if info.LogLine == nil || info.LogLine.Severity != 2 || info.LogLine.Line != "" {
		t.Fatalf("unexpected log frame: %+v", info)
	}
}

func TestBandwidthWireSizesMatchDecodedTypes(t *testing.T) {
	if got := binary.Size(BandwidthValueV4{}); got != bandwidthValueV4Size {
		t.Fatalf("IPv4 bandwidth size changed: got %d, want %d", got, bandwidthValueV4Size)
	}
	if got := binary.Size(BandwidthValueV6{}); got != bandwidthValueV6Size {
		t.Fatalf("IPv6 bandwidth size changed: got %d, want %d", got, bandwidthValueV6Size)
	}
}
