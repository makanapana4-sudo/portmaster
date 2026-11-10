package kextinterface

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	InfoLogLine              = 0
	InfoConnectionIpv4       = 1
	InfoConnectionIpv6       = 2
	InfoConnectionEndEventV4 = 3
	InfoConnectionEndEventV6 = 4
	InfoBandwidthStatsV4     = 5
	InfoBandwidthStatsV6     = 6

	maxInfoPayloadSize    = 16 << 20
	bandwidthValueV4Size = 28
	bandwidthValueV6Size = 52
	bandwidthBatchRecords = 64
	bandwidthBatchBytes = bandwidthBatchRecords * bandwidthValueV6Size
)

var (
	ErrUnknownInfoType     = errors.New("unknown info type")
	ErrUnexpectedInfoSize  = errors.New("unexpected info size")
	ErrUnexpectedReadError = errors.New("unexpected read error")
	ErrInfoPayloadTooLarge = errors.New("info payload exceeds the maximum allowed size")
)

type connectionV4Internal struct {
	ID           uint64
	ProcessID    uint64
	Direction    byte
	Protocol     byte
	LocalIP      [4]byte
	RemoteIP     [4]byte
	LocalPort    uint16
	RemotePort   uint16
	PayloadLayer uint8
}

type ConnectionV4 struct {
	connectionV4Internal
	Payload []byte
}

func (c *ConnectionV4) Compare(other *ConnectionV4) bool {
	return c.ID == other.ID &&
		c.ProcessID == other.ProcessID &&
		c.Direction == other.Direction &&
		c.Protocol == other.Protocol &&
		c.LocalIP == other.LocalIP &&
		c.RemoteIP == other.RemoteIP &&
		c.LocalPort == other.LocalPort &&
		c.RemotePort == other.RemotePort
}

type connectionV6Internal struct {
	ID           uint64
	ProcessID    uint64
	Direction    byte
	Protocol     byte
	LocalIP      [16]byte
	RemoteIP     [16]byte
	LocalPort    uint16
	RemotePort   uint16
	PayloadLayer uint8
}

type ConnectionV6 struct {
	connectionV6Internal
	Payload []byte
}

func (c ConnectionV6) Compare(other *ConnectionV6) bool {
	return c.ID == other.ID &&
		c.ProcessID == other.ProcessID &&
		c.Direction == other.Direction &&
		c.Protocol == other.Protocol &&
		c.LocalIP == other.LocalIP &&
		c.RemoteIP == other.RemoteIP &&
		c.LocalPort == other.LocalPort &&
		c.RemotePort == other.RemotePort
}

type ConnectionEndV4 struct {
	ProcessID  uint64
	Direction  byte
	Protocol   byte
	LocalIP    [4]byte
	RemoteIP   [4]byte
	LocalPort  uint16
	RemotePort uint16
}

type ConnectionEndV6 struct {
	ProcessID  uint64
	Direction  byte
	Protocol   byte
	LocalIP    [16]byte
	RemoteIP   [16]byte
	LocalPort  uint16
	RemotePort uint16
}

type LogLine struct {
	Severity byte
	Line     string
}

type BandwidthValueV4 struct {
	LocalIP          [4]byte
	LocalPort        uint16
	RemoteIP         [4]byte
	RemotePort       uint16
	TransmittedBytes uint64
	ReceivedBytes    uint64
}

type BandwidthValueV6 struct {
	LocalIP          [16]byte
	LocalPort        uint16
	RemoteIP         [16]byte
	RemotePort       uint16
	TransmittedBytes uint64
	ReceivedBytes    uint64
}

type BandwidthStatsArray struct {
	Protocol uint8
	ValuesV4 []BandwidthValueV4
	ValuesV6 []BandwidthValueV6
}

type Info struct {
	ConnectionV4    *ConnectionV4
	ConnectionV6    *ConnectionV6
	ConnectionEndV4 *ConnectionEndV4
	ConnectionEndV6 *ConnectionEndV6
	LogLine         *LogLine
	BandwidthStats  *BandwidthStatsArray
}

type readHelper struct {
	infoType    byte
	commandSize uint32
	readSize    int
	reader      io.Reader
}

func newReadHelper(reader io.Reader) (*readHelper, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}

	return &readHelper{
		infoType:    header[0],
		commandSize: binary.LittleEndian.Uint32(header[1:]),
		reader:      reader,
	}, nil
}

func (r *readHelper) remaining() (uint64, error) {
	if r.readSize < 0 || uint64(r.readSize) > uint64(r.commandSize) {
		return 0, ErrUnexpectedInfoSize
	}
	return uint64(r.commandSize) - uint64(r.readSize), nil
}

// ReadFixed reads a fixed-size field without reflection or temporary buffers.
func (r *readHelper) ReadFixed(output []byte) error {
	remaining, err := r.remaining()
	if err != nil {
		return err
	}
	if uint64(len(output)) > remaining {
		return ErrUnexpectedInfoSize
	}
	if len(output) == 0 {
		return nil
	}
	if _, err := io.ReadFull(r, output); err != nil {
		return errors.Join(ErrUnexpectedReadError, err)
	}
	return nil
}

func (r *readHelper) ReadUint8() (uint8, error) {
	var raw [1]byte
	if err := r.ReadFixed(raw[:]); err != nil {
		return 0, err
	}
	return raw[0], nil
}

func (r *readHelper) ReadUint32() (uint32, error) {
	var raw [4]byte
	if err := r.ReadFixed(raw[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw[:]), nil
}

func (r *readHelper) readConnectionV4() (connectionV4Internal, error) {
	var raw [31]byte
	if err := r.ReadFixed(raw[:]); err != nil {
		return connectionV4Internal{}, err
	}

	value := connectionV4Internal{
		ID:           binary.LittleEndian.Uint64(raw[0:8]),
		ProcessID:    binary.LittleEndian.Uint64(raw[8:16]),
		Direction:    raw[16],
		Protocol:     raw[17],
		LocalPort:    binary.LittleEndian.Uint16(raw[26:28]),
		RemotePort:   binary.LittleEndian.Uint16(raw[28:30]),
		PayloadLayer: raw[30],
	}
	copy(value.LocalIP[:], raw[18:22])
	copy(value.RemoteIP[:], raw[22:26])
	return value, nil
}

func (r *readHelper) readConnectionV6() (connectionV6Internal, error) {
	var raw [55]byte
	if err := r.ReadFixed(raw[:]); err != nil {
		return connectionV6Internal{}, err
	}

	value := connectionV6Internal{
		ID:           binary.LittleEndian.Uint64(raw[0:8]),
		ProcessID:    binary.LittleEndian.Uint64(raw[8:16]),
		Direction:    raw[16],
		Protocol:     raw[17],
		LocalPort:    binary.LittleEndian.Uint16(raw[50:52]),
		RemotePort:   binary.LittleEndian.Uint16(raw[52:54]),
		PayloadLayer: raw[54],
	}
	copy(value.LocalIP[:], raw[18:34])
	copy(value.RemoteIP[:], raw[34:50])
	return value, nil
}

func (r *readHelper) readConnectionEndV4() (ConnectionEndV4, error) {
	var raw [22]byte
	if err := r.ReadFixed(raw[:]); err != nil {
		return ConnectionEndV4{}, err
	}

	value := ConnectionEndV4{
		ProcessID:  binary.LittleEndian.Uint64(raw[0:8]),
		Direction:  raw[8],
		Protocol:   raw[9],
		LocalPort:  binary.LittleEndian.Uint16(raw[18:20]),
		RemotePort: binary.LittleEndian.Uint16(raw[20:22]),
	}
	copy(value.LocalIP[:], raw[10:14])
	copy(value.RemoteIP[:], raw[14:18])
	return value, nil
}

func (r *readHelper) readConnectionEndV6() (ConnectionEndV6, error) {
	var raw [46]byte
	if err := r.ReadFixed(raw[:]); err != nil {
		return ConnectionEndV6{}, err
	}

	value := ConnectionEndV6{
		ProcessID:  binary.LittleEndian.Uint64(raw[0:8]),
		Direction:  raw[8],
		Protocol:   raw[9],
		LocalPort:  binary.LittleEndian.Uint16(raw[42:44]),
		RemotePort: binary.LittleEndian.Uint16(raw[44:46]),
	}
	copy(value.LocalIP[:], raw[10:26])
	copy(value.RemoteIP[:], raw[26:42])
	return value, nil
}

func (r *readHelper) readBandwidthValuesV4(count uint32) ([]BandwidthValueV4, error) {
	if err := r.validateArrayCount(count, bandwidthValueV4Size); err != nil {
		return nil, err
	}

	values := make([]BandwidthValueV4, int(count))
	var batch [bandwidthBatchBytes]byte

	for offset := 0; offset < len(values); {
		batchCount := len(values) - offset
		if batchCount > bandwidthBatchRecords {
			batchCount = bandwidthBatchRecords
		}
		batchSize := batchCount * bandwidthValueV4Size
		if err := r.ReadFixed(batch[:batchSize]); err != nil {
			return nil, err
		}

		for index := 0; index < batchCount; index++ {
			raw := batch[index*bandwidthValueV4Size : (index+1)*bandwidthValueV4Size]
			value := BandwidthValueV4{
				LocalPort:        binary.LittleEndian.Uint16(raw[4:6]),
				RemotePort:       binary.LittleEndian.Uint16(raw[10:12]),
				TransmittedBytes: binary.LittleEndian.Uint64(raw[12:20]),
				ReceivedBytes:    binary.LittleEndian.Uint64(raw[20:28]),
			}
			copy(value.LocalIP[:], raw[0:4])
			copy(value.RemoteIP[:], raw[6:10])
			values[offset+index] = value
		}

		offset += batchCount
	}

	return values, nil
}

func (r *readHelper) readBandwidthValuesV6(count uint32) ([]BandwidthValueV6, error) {
	if err := r.validateArrayCount(count, bandwidthValueV6Size); err != nil {
		return nil, err
	}

	values := make([]BandwidthValueV6, int(count))
	var batch [bandwidthBatchBytes]byte

	for offset := 0; offset < len(values); {
		batchCount := len(values) - offset
		if batchCount > bandwidthBatchRecords {
			batchCount = bandwidthBatchRecords
		}
		batchSize := batchCount * bandwidthValueV6Size
		if err := r.ReadFixed(batch[:batchSize]); err != nil {
			return nil, err
		}

		for index := 0; index < batchCount; index++ {
			raw := batch[index*bandwidthValueV6Size : (index+1)*bandwidthValueV6Size]
			value := BandwidthValueV6{
				LocalPort:        binary.LittleEndian.Uint16(raw[16:18]),
				RemotePort:       binary.LittleEndian.Uint16(raw[34:36]),
				TransmittedBytes: binary.LittleEndian.Uint64(raw[36:44]),
				ReceivedBytes:    binary.LittleEndian.Uint64(raw[44:52]),
			}
			copy(value.LocalIP[:], raw[0:16])
			copy(value.RemoteIP[:], raw[18:34])
			values[offset+index] = value
		}

		offset += batchCount
	}

	return values, nil
}

func (r *readHelper) validateArrayCount(count uint32, elementSize uint32) error {
	if elementSize == 0 {
		return ErrUnexpectedInfoSize
	}

	remaining, err := r.remaining()
	if err != nil {
		return err
	}
	if uint64(count)*uint64(elementSize) > remaining {
		return ErrUnexpectedInfoSize
	}
	return nil
}

// Passing size = 0 reads the rest of the current command.
func (r *readHelper) ReadBytes(size uint32) ([]byte, error) {
	remaining, err := r.remaining()
	if err != nil {
		return nil, err
	}

	if size == 0 {
		size = uint32(remaining)
	} else if uint64(size) > remaining {
		return nil, ErrUnexpectedInfoSize
	}

	if size == 0 {
		return []byte{}, nil
	}

	data := make([]byte, int(size))
	if err := r.ReadFixed(data); err != nil {
		return nil, err
	}

	return data, nil
}

// ReadUntilTheEnd discards unread bytes without allocating a buffer the size
// of the remaining frame. This keeps error recovery bounded in memory.
func (r *readHelper) ReadUntilTheEnd() {
	remaining, err := r.remaining()
	if err != nil || remaining == 0 {
		return
	}
	_, _ = io.CopyN(io.Discard, r, int64(remaining))
}

func (r *readHelper) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.readSize += n
	return n, err
}

func RecvInfo(reader io.Reader) (*Info, error) {
	helper, err := newReadHelper(reader)
	if err != nil {
		return nil, err
	}

	if helper.commandSize > maxInfoPayloadSize {
		return nil, fmt.Errorf("%w: %d bytes (maximum %d)", ErrInfoPayloadTooLarge, helper.commandSize, maxInfoPayloadSize)
	}

	// Keep subsequent frames aligned without allocating the entire remainder.
	defer helper.ReadUntilTheEnd()

	switch helper.infoType {
	case InfoConnectionIpv4:
		newInfo := ConnectionV4{}
		fixedSizeValues, readErr := helper.readConnectionV4()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoConnectionIpv4 fixed fields: %w", readErr)
		}
		newInfo.connectionV4Internal = fixedSizeValues

		payloadSize, readErr := helper.ReadUint32()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoConnectionIpv4 payload size: %w", readErr)
		}
		if payloadSize > 0 {
			newInfo.Payload, readErr = helper.ReadBytes(payloadSize)
			if readErr != nil {
				return nil, fmt.Errorf("failed to parse InfoConnectionIpv4 payload: %w", readErr)
			}
		}
		return &Info{ConnectionV4: &newInfo}, nil

	case InfoConnectionIpv6:
		newInfo := ConnectionV6{}
		fixedSizeValues, readErr := helper.readConnectionV6()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoConnectionIpv6 fixed fields: %w", readErr)
		}
		newInfo.connectionV6Internal = fixedSizeValues

		payloadSize, readErr := helper.ReadUint32()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoConnectionIpv6 payload size: %w", readErr)
		}
		if payloadSize > 0 {
			newInfo.Payload, readErr = helper.ReadBytes(payloadSize)
			if readErr != nil {
				return nil, fmt.Errorf("failed to parse InfoConnectionIpv6 payload: %w", readErr)
			}
		}
		return &Info{ConnectionV6: &newInfo}, nil

	case InfoConnectionEndEventV4:
		connectionEnd, readErr := helper.readConnectionEndV4()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoConnectionEndEventV4: %w", readErr)
		}
		return &Info{ConnectionEndV4: &connectionEnd}, nil

	case InfoConnectionEndEventV6:
		connectionEnd, readErr := helper.readConnectionEndV6()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoConnectionEndEventV6: %w", readErr)
		}
		return &Info{ConnectionEndV6: &connectionEnd}, nil

	case InfoLogLine:
		severity, readErr := helper.ReadUint8()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoLogLine severity: %w", readErr)
		}
		line, readErr := helper.ReadBytes(0)
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoLogLine message: %w", readErr)
		}
		return &Info{LogLine: &LogLine{
			Severity: severity,
			Line:     string(line),
		}}, nil

	case InfoBandwidthStatsV4:
		protocol, readErr := helper.ReadUint8()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoBandwidthStatsV4 protocol: %w", readErr)
		}
		size, readErr := helper.ReadUint32()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoBandwidthStatsV4 count: %w", readErr)
		}
		statsArray, readErr := helper.readBandwidthValuesV4(size)
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoBandwidthStatsV4 records: %w", readErr)
		}
		return &Info{BandwidthStats: &BandwidthStatsArray{Protocol: protocol, ValuesV4: statsArray}}, nil

	case InfoBandwidthStatsV6:
		protocol, readErr := helper.ReadUint8()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoBandwidthStatsV6 protocol: %w", readErr)
		}
		size, readErr := helper.ReadUint32()
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoBandwidthStatsV6 count: %w", readErr)
		}
		statsArray, readErr := helper.readBandwidthValuesV6(size)
		if readErr != nil {
			return nil, fmt.Errorf("failed to parse InfoBandwidthStatsV6 records: %w", readErr)
		}
		return &Info{BandwidthStats: &BandwidthStatsArray{Protocol: protocol, ValuesV6: statsArray}}, nil
	}

	return nil, ErrUnknownInfoType
}
