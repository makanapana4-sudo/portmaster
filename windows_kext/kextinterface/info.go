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
	helper := &readHelper{reader: reader}

	err := binary.Read(reader, binary.LittleEndian, &helper.infoType)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.LittleEndian, &helper.commandSize)
	if err != nil {
		return nil, err
	}

	return helper, nil
}

func (r *readHelper) remaining() (uint64, error) {
	if r.readSize < 0 || uint64(r.readSize) > uint64(r.commandSize) {
		return 0, ErrUnexpectedInfoSize
	}
	return uint64(r.commandSize) - uint64(r.readSize), nil
}

func (r *readHelper) ReadData(data any) error {
	size := binary.Size(data)
	remaining, err := r.remaining()
	if err != nil {
		return err
	}
	if size < 0 || uint64(size) > remaining {
		return ErrUnexpectedInfoSize
	}

	if err := binary.Read(r, binary.LittleEndian, data); err != nil {
		return errors.Join(ErrUnexpectedReadError, err)
	}

	return nil
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
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, errors.Join(ErrUnexpectedReadError, err)
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
		parseError := fmt.Errorf("failed to parse InfoConnectionIpv4")
		newInfo := ConnectionV4{}
		var fixedSizeValues connectionV4Internal
		if err = helper.ReadData(&fixedSizeValues); err != nil {
			return nil, errors.Join(parseError, err, fmt.Errorf("fixed"))
		}
		newInfo.connectionV4Internal = fixedSizeValues

		var payloadSize uint32
		if err = helper.ReadData(&payloadSize); err != nil {
			return nil, errors.Join(parseError, err, fmt.Errorf("payloadsize"))
		}
		if payloadSize > 0 {
			newInfo.Payload, err = helper.ReadBytes(payloadSize)
			if err != nil {
				return nil, errors.Join(parseError, err, fmt.Errorf("payload"))
			}
		}
		return &Info{ConnectionV4: &newInfo}, nil

	case InfoConnectionIpv6:
		parseError := fmt.Errorf("failed to parse InfoConnectionIpv6")
		newInfo := ConnectionV6{}
		if err = helper.ReadData(&newInfo.connectionV6Internal); err != nil {
			return nil, errors.Join(parseError, err)
		}

		var payloadSize uint32
		if err = helper.ReadData(&payloadSize); err != nil {
			return nil, errors.Join(parseError, err)
		}
		if payloadSize > 0 {
			newInfo.Payload, err = helper.ReadBytes(payloadSize)
			if err != nil {
				return nil, errors.Join(parseError, err)
			}
		}
		return &Info{ConnectionV6: &newInfo}, nil

	case InfoConnectionEndEventV4:
		var connectionEnd ConnectionEndV4
		if err = helper.ReadData(&connectionEnd); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoConnectionEndEventV4"), err)
		}
		return &Info{ConnectionEndV4: &connectionEnd}, nil

	case InfoConnectionEndEventV6:
		var connectionEnd ConnectionEndV6
		if err = helper.ReadData(&connectionEnd); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoConnectionEndEventV6"), err)
		}
		return &Info{ConnectionEndV6: &connectionEnd}, nil

	case InfoLogLine:
		logLine := LogLine{}
		if err = helper.ReadData(&logLine.Severity); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoLogLine"), err)
		}
		line, readErr := helper.ReadBytes(0)
		if readErr != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoLogLine"), readErr)
		}
		logLine.Line = string(line)
		return &Info{LogLine: &logLine}, nil

	case InfoBandwidthStatsV4:
		var protocol uint8
		if err = helper.ReadData(&protocol); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV4"), err)
		}
		var size uint32
		if err = helper.ReadData(&size); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV4"), err)
		}
		if err = helper.validateArrayCount(size, bandwidthValueV4Size); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV4"), err)
		}

		statsArray := make([]BandwidthValueV4, int(size))
		for i := range statsArray {
			if err = helper.ReadData(&statsArray[i]); err != nil {
				return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV4"), err)
			}
		}
		return &Info{BandwidthStats: &BandwidthStatsArray{Protocol: protocol, ValuesV4: statsArray}}, nil

	case InfoBandwidthStatsV6:
		var protocol uint8
		if err = helper.ReadData(&protocol); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV6"), err)
		}
		var size uint32
		if err = helper.ReadData(&size); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV6"), err)
		}
		if err = helper.validateArrayCount(size, bandwidthValueV6Size); err != nil {
			return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV6"), err)
		}

		statsArray := make([]BandwidthValueV6, int(size))
		for i := range statsArray {
			if err = helper.ReadData(&statsArray[i]); err != nil {
				return nil, errors.Join(fmt.Errorf("failed to parse InfoBandwidthStatsV6"), err)
			}
		}
		return &Info{BandwidthStats: &BandwidthStatsArray{Protocol: protocol, ValuesV6: statsArray}}, nil
	}

	return nil, ErrUnknownInfoType
}
