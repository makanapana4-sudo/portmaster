package kextinterface

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
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

func TestFixedWireSizesMatchGoTypes(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"connection v4", binary.Size(connectionV4Internal{}), 31},
		{"connection v6", binary.Size(connectionV6Internal{}), 55},
		{"connection end v4", binary.Size(ConnectionEndV4{}), 22},
		{"connection end v6", binary.Size(ConnectionEndV6{}), 46},
		{"bandwidth v4", binary.Size(BandwidthValueV4{}), bandwidthValueV4Size},
		{"bandwidth v6", binary.Size(BandwidthValueV6{}), bandwidthValueV6Size},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("wire size mismatch: got %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestRecvInfoDecodesFixedConnectionFields(t *testing.T) {
	v4Payload := make([]byte, 31+4+2)
	binary.LittleEndian.PutUint64(v4Payload[0:8], 100)
	binary.LittleEndian.PutUint64(v4Payload[8:16], 200)
	v4Payload[16] = 1
	v4Payload[17] = 6
	copy(v4Payload[18:22], []byte{10, 0, 0, 1})
	copy(v4Payload[22:26], []byte{1, 1, 1, 1})
	binary.LittleEndian.PutUint16(v4Payload[26:28], 1234)
	binary.LittleEndian.PutUint16(v4Payload[28:30], 443)
	v4Payload[30] = 2
	binary.LittleEndian.PutUint32(v4Payload[31:35], 2)
	copy(v4Payload[35:], []byte{7, 8})

	v4Info, err := RecvInfo(bytes.NewReader(makeInfoFrame(InfoConnectionIpv4, v4Payload)))
	if err != nil {
		t.Fatal(err)
	}
	if v4Info.ConnectionV4 == nil {
		t.Fatal("expected an IPv4 connection")
	}
	wantV4 := connectionV4Internal{
		ID:           100,
		ProcessID:    200,
		Direction:    1,
		Protocol:     6,
		LocalIP:      [4]byte{10, 0, 0, 1},
		RemoteIP:     [4]byte{1, 1, 1, 1},
		LocalPort:    1234,
		RemotePort:   443,
		PayloadLayer: 2,
	}
	if v4Info.ConnectionV4.connectionV4Internal != wantV4 {
		t.Fatalf("IPv4 fields differ: got %+v, want %+v", v4Info.ConnectionV4.connectionV4Internal, wantV4)
	}
	if !bytes.Equal(v4Info.ConnectionV4.Payload, []byte{7, 8}) {
		t.Fatalf("unexpected IPv4 payload: %v", v4Info.ConnectionV4.Payload)
	}

	v6Payload := make([]byte, 55+4+1)
	binary.LittleEndian.PutUint64(v6Payload[0:8], 300)
	binary.LittleEndian.PutUint64(v6Payload[8:16], 400)
	v6Payload[16] = 0
	v6Payload[17] = 17
	copy(v6Payload[18:34], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	copy(v6Payload[34:50], []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	binary.LittleEndian.PutUint16(v6Payload[50:52], 5353)
	binary.LittleEndian.PutUint16(v6Payload[52:54], 443)
	v6Payload[54] = 3
	binary.LittleEndian.PutUint32(v6Payload[55:59], 1)
	v6Payload[59] = 9

	v6Info, err := RecvInfo(bytes.NewReader(makeInfoFrame(InfoConnectionIpv6, v6Payload)))
	if err != nil {
		t.Fatal(err)
	}
	if v6Info.ConnectionV6 == nil {
		t.Fatal("expected an IPv6 connection")
	}
	if v6Info.ConnectionV6.ID != 300 ||
		v6Info.ConnectionV6.ProcessID != 400 ||
		v6Info.ConnectionV6.Protocol != 17 ||
		v6Info.ConnectionV6.LocalPort != 5353 ||
		v6Info.ConnectionV6.RemotePort != 443 ||
		v6Info.ConnectionV6.PayloadLayer != 3 {
		t.Fatalf("unexpected IPv6 connection fields: %+v", v6Info.ConnectionV6)
	}
	if !bytes.Equal(v6Info.ConnectionV6.Payload, []byte{9}) {
		t.Fatalf("unexpected IPv6 payload: %v", v6Info.ConnectionV6.Payload)
	}
}

func BenchmarkRecvInfoConnectionV4(b *testing.B) {
	payload := make([]byte, 31+4)
	binary.LittleEndian.PutUint64(payload[0:8], 1)
	binary.LittleEndian.PutUint64(payload[8:16], 2)
	payload[17] = 6
	binary.LittleEndian.PutUint16(payload[26:28], 1234)
	binary.LittleEndian.PutUint16(payload[28:30], 443)
	frame := makeInfoFrame(InfoConnectionIpv4, payload)
	reader := bytes.NewReader(frame)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(frame)
		if _, err := RecvInfo(reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecvInfoBandwidthV4(b *testing.B) {
	const recordCount = 128
	payload := make([]byte, 5+recordCount*bandwidthValueV4Size)
	payload[0] = 6
	binary.LittleEndian.PutUint32(payload[1:5], recordCount)
	for i := 0; i < recordCount; i++ {
		offset := 5 + i*bandwidthValueV4Size
		binary.LittleEndian.PutUint16(payload[offset+4:offset+6], uint16(1000+i))
		binary.LittleEndian.PutUint16(payload[offset+10:offset+12], 443)
		binary.LittleEndian.PutUint64(payload[offset+12:offset+20], uint64(i))
		binary.LittleEndian.PutUint64(payload[offset+20:offset+28], uint64(i*2))
	}

	frame := makeInfoFrame(InfoBandwidthStatsV4, payload)
	reader := bytes.NewReader(frame)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(frame)
		if _, err := RecvInfo(reader); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRecvInfoAcceptsEmptyBandwidthArrays(t *testing.T) {
	for _, infoType := range []byte{InfoBandwidthStatsV4, InfoBandwidthStatsV6} {
		payload := make([]byte, 5)
		payload[0] = 6
		frame := makeInfoFrame(infoType, payload)

		info, err := RecvInfo(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("type %d: %v", infoType, err)
		}
		if info.BandwidthStats == nil {
			t.Fatalf("type %d: expected bandwidth stats", infoType)
		}
		if infoType == InfoBandwidthStatsV4 && len(info.BandwidthStats.ValuesV4) != 0 {
			t.Fatalf("unexpected IPv4 bandwidth entries: %d", len(info.BandwidthStats.ValuesV4))
		}
		if infoType == InfoBandwidthStatsV6 && len(info.BandwidthStats.ValuesV6) != 0 {
			t.Fatalf("unexpected IPv6 bandwidth entries: %d", len(info.BandwidthStats.ValuesV6))
		}
	}
}

type oneByteReader struct {
	source *bytes.Reader
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.source.Read(p)
}

func TestRecvInfoHandlesFragmentedReads(t *testing.T) {
	frame := makeInfoFrame(InfoLogLine, []byte{4, 's', 'p', 'l', 'i', 't'})
	reader := &oneByteReader{source: bytes.NewReader(frame)}

	info, err := RecvInfo(reader)
	if err != nil {
		t.Fatal(err)
	}
	if info.LogLine == nil {
		t.Fatal("expected a log line")
	}
	if info.LogLine.Severity != 4 || info.LogLine.Line != "split" {
		t.Fatalf("unexpected log line: %+v", info.LogLine)
	}
}

func TestRecvInfoDecodesBandwidthAcrossBatchBoundary(t *testing.T) {
	const recordCount = bandwidthBatchRecords + 3
	payload := make([]byte, 5+recordCount*bandwidthValueV4Size)
	payload[0] = 6
	binary.LittleEndian.PutUint32(payload[1:5], recordCount)

	for index := 0; index < recordCount; index++ {
		offset := 5 + index*bandwidthValueV4Size
		payload[offset] = byte(index)
		binary.LittleEndian.PutUint16(payload[offset+4:offset+6], uint16(1000+index))
		payload[offset+6] = byte(index + 1)
		binary.LittleEndian.PutUint16(payload[offset+10:offset+12], 443)
		binary.LittleEndian.PutUint64(payload[offset+12:offset+20], uint64(index+10))
		binary.LittleEndian.PutUint64(payload[offset+20:offset+28], uint64(index+20))
	}

	info, err := RecvInfo(bytes.NewReader(makeInfoFrame(InfoBandwidthStatsV4, payload)))
	if err != nil {
		t.Fatal(err)
	}
	if info.BandwidthStats == nil {
		t.Fatal("expected bandwidth statistics")
	}
	values := info.BandwidthStats.ValuesV4
	if len(values) != recordCount {
		t.Fatalf("got %d records, want %d", len(values), recordCount)
	}

	last := values[recordCount-1]
	if last.LocalIP[0] != byte(recordCount-1) ||
		last.LocalPort != uint16(1000+recordCount-1) ||
		last.RemoteIP[0] != byte(recordCount) ||
		last.RemotePort != 443 ||
		last.TransmittedBytes != uint64(recordCount+9) ||
		last.ReceivedBytes != uint64(recordCount+19) {
		t.Fatalf("last record decoded incorrectly: %+v", last)
	}
}

var (
	benchmarkInfoSink      *Info
	benchmarkBandwidthSink []BandwidthValueV4
)

func BenchmarkRecvInfoConnectionV4BinaryReadBaseline(b *testing.B) {
	payload := make([]byte, 31+4+4)
	binary.LittleEndian.PutUint64(payload[0:8], 123)
	binary.LittleEndian.PutUint64(payload[8:16], 456)
	payload[17] = 6
	binary.LittleEndian.PutUint16(payload[26:28], 1234)
	binary.LittleEndian.PutUint16(payload[28:30], 443)
	binary.LittleEndian.PutUint32(payload[31:35], 4)
	copy(payload[35:], []byte{1, 2, 3, 4})

	frame := makeInfoFrame(InfoConnectionIpv4, payload)
	reader := bytes.NewReader(frame[5:])

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(frame[5:])
		parsed := &ConnectionV4{}
		if err := binary.Read(reader, binary.LittleEndian, &parsed.connectionV4Internal); err != nil {
			b.Fatal(err)
		}

		var payloadSize uint32
		if err := binary.Read(reader, binary.LittleEndian, &payloadSize); err != nil {
			b.Fatal(err)
		}
		parsed.Payload = make([]byte, int(payloadSize))
		if _, err := io.ReadFull(reader, parsed.Payload); err != nil {
			b.Fatal(err)
		}
		benchmarkInfoSink = &Info{ConnectionV4: parsed}
	}
}

func BenchmarkRecvInfoBandwidthV4BinaryReadBaseline(b *testing.B) {
	const recordCount = 128
	payload := make([]byte, 5+recordCount*bandwidthValueV4Size)
	payload[0] = 6
	binary.LittleEndian.PutUint32(payload[1:5], recordCount)
	for i := 0; i < recordCount; i++ {
		offset := 5 + i*bandwidthValueV4Size
		binary.LittleEndian.PutUint16(payload[offset+4:offset+6], uint16(1000+i))
		binary.LittleEndian.PutUint16(payload[offset+10:offset+12], 443)
		binary.LittleEndian.PutUint64(payload[offset+12:offset+20], uint64(i))
		binary.LittleEndian.PutUint64(payload[offset+20:offset+28], uint64(i*2))
	}

	frame := makeInfoFrame(InfoBandwidthStatsV4, payload)
	reader := bytes.NewReader(frame[5:])

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(frame[5:])

		var protocol uint8
		if err := binary.Read(reader, binary.LittleEndian, &protocol); err != nil {
			b.Fatal(err)
		}
		var count uint32
		if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
			b.Fatal(err)
		}

		values := make([]BandwidthValueV4, int(count))
		for index := range values {
			if err := binary.Read(reader, binary.LittleEndian, &values[index]); err != nil {
				b.Fatal(err)
			}
		}
		benchmarkBandwidthSink = values
	}
}
