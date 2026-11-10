package kextinterface

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type chunkWriter struct {
	bytes.Buffer
	maxChunk int
}

func (w *chunkWriter) Write(data []byte) (int, error) {
	if len(data) > w.maxChunk {
		data = data[:w.maxChunk]
	}
	return w.Buffer.Write(data)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}

func TestSendVerdictCommandUsesDriverWireLayout(t *testing.T) {
	var output bytes.Buffer

	err := SendVerdictCommand(&output, Verdict{
		ID:      0x0102030405060708,
		Verdict: 9,
	})
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{CommandVerdict, 8, 7, 6, 5, 4, 3, 2, 1, 9}
	if !bytes.Equal(output.Bytes(), expected) {
		t.Fatalf("unexpected command bytes: got %v, want %v", output.Bytes(), expected)
	}
}

func TestSendUpdateV4CommandUsesDriverWireLayout(t *testing.T) {
	var output bytes.Buffer

	err := SendUpdateV4Command(&output, UpdateV4{
		Protocol:      6,
		LocalAddress:  [4]byte{10, 0, 0, 1},
		LocalPort:     0x1234,
		RemoteAddress: [4]byte{1, 1, 1, 1},
		RemotePort:    443,
		Verdict:       byte(VerdictAccept),
	})
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		CommandUpdateV4, 6,
		10, 0, 0, 1, 0x34, 0x12,
		1, 1, 1, 1, 0xbb, 0x01,
		byte(VerdictAccept),
	}
	if !bytes.Equal(output.Bytes(), expected) {
		t.Fatalf("unexpected command bytes: got %v, want %v", output.Bytes(), expected)
	}
}

func TestSendUpdateV6CommandUsesDriverWireLayout(t *testing.T) {
	var output bytes.Buffer

	err := SendUpdateV6Command(&output, UpdateV6{
		Protocol:      17,
		LocalAddress:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		LocalPort:     0x1234,
		RemoteAddress: [16]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		RemotePort:    0x5678,
		Verdict:       byte(VerdictBlock),
	})
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		CommandUpdateV6, 17,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		0x34, 0x12,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		0x78, 0x56,
		byte(VerdictBlock),
	}
	if !bytes.Equal(output.Bytes(), expected) {
		t.Fatalf("unexpected command bytes: got %v, want %v", output.Bytes(), expected)
	}
}

func TestWriteCommandHandlesShortWrites(t *testing.T) {
	output := &chunkWriter{maxChunk: 2}
	command := []byte{1, 2, 3, 4, 5, 6}

	if err := writeCommand(output, command); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), command) {
		t.Fatalf("partial writer received %v, want %v", output.Bytes(), command)
	}
}

func TestWriteCommandRejectsZeroByteWrite(t *testing.T) {
	err := writeCommand(zeroWriter{}, []byte{1})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v", err)
	}
}

func TestSimpleCommandsUseSingleByteIDs(t *testing.T) {
	tests := []struct {
		name string
		send func(io.Writer) error
		want byte
	}{
		{"shutdown", SendShutdownCommand, CommandShutdown},
		{"clear cache", SendClearCacheCommand, CommandClearCache},
		{"get logs", SendGetLogsCommand, CommandGetLogs},
		{"bandwidth", SendGetBandwidthStatsCommand, CommandBandwidthStats},
		{"memory stats", SendPrintMemoryStatsCommand, CommandPrintMemoryStats},
		{"clean ended connections", SendCleanEndedConnectionsCommand, CommandCleanEndedConnections},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := test.send(&output); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), []byte{test.want}) {
				t.Fatalf("got %v, want [%d]", output.Bytes(), test.want)
			}
		})
	}
}
