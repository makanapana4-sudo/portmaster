package kextinterface

import (
	"encoding/binary"
	"io"
)

// Command IDs.
const (
	CommandShutdown              = 0
	CommandVerdict               = 1
	CommandUpdateV4              = 2
	CommandUpdateV6              = 3
	CommandClearCache            = 4
	CommandGetLogs               = 5
	CommandBandwidthStats        = 6
	CommandPrintMemoryStats      = 7
	CommandCleanEndedConnections = 8
)

// KextVerdict is the verdict ID used to with the kext.
type KextVerdict uint8

// Kext Verdicts.
// Make sure this is in sync with the Rust version.
const (
	// VerdictUndecided is the default status of new connections.
	VerdictUndecided           KextVerdict = 0
	VerdictUndeterminable      KextVerdict = 1
	VerdictAccept              KextVerdict = 2
	VerdictPermanentAccept     KextVerdict = 3
	VerdictBlock               KextVerdict = 4
	VerdictPermanentBlock      KextVerdict = 5
	VerdictDrop                KextVerdict = 6
	VerdictPermanentDrop       KextVerdict = 7
	VerdictRerouteToNameserver KextVerdict = 8
	VerdictRerouteToTunnel     KextVerdict = 9
	VerdictFailed              KextVerdict = 10
	VerdictRerouteToSplitTun   KextVerdict = 11
)

type Verdict struct {
	command uint8
	ID      uint64
	Verdict uint8
}

type UpdateV4 struct {
	command       uint8
	Protocol      uint8
	LocalAddress  [4]byte
	LocalPort     uint16
	RemoteAddress [4]byte
	RemotePort    uint16
	Verdict       uint8
}

type UpdateV6 struct {
	command       uint8
	Protocol      uint8
	LocalAddress  [16]byte
	LocalPort     uint16
	RemoteAddress [16]byte
	RemotePort    uint16
	Verdict       uint8
}

// writeCommand handles short writes so a partial driver command is never
// treated as successfully delivered.
func writeCommand(writer io.Writer, command []byte) error {
	for len(command) > 0 {
		written, err := writer.Write(command)
		if written > 0 {
			command = command[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// SendShutdownCommand sends a Shutdown command to the kext.
func SendShutdownCommand(writer io.Writer) error {
	return writeCommand(writer, []byte{CommandShutdown})
}

// SendVerdictCommand sends a Verdict command to the kext.
func SendVerdictCommand(writer io.Writer, verdict Verdict) error {
	var command [10]byte
	command[0] = CommandVerdict
	binary.LittleEndian.PutUint64(command[1:9], verdict.ID)
	command[9] = verdict.Verdict
	return writeCommand(writer, command[:])
}

// SendUpdateV4Command sends a UpdateV4 command to the kext.
func SendUpdateV4Command(writer io.Writer, update UpdateV4) error {
	var command [15]byte
	command[0] = CommandUpdateV4
	command[1] = update.Protocol
	copy(command[2:6], update.LocalAddress[:])
	binary.LittleEndian.PutUint16(command[6:8], update.LocalPort)
	copy(command[8:12], update.RemoteAddress[:])
	binary.LittleEndian.PutUint16(command[12:14], update.RemotePort)
	command[14] = update.Verdict
	return writeCommand(writer, command[:])
}

// SendUpdateV6Command sends a UpdateV6 command to the kext.
func SendUpdateV6Command(writer io.Writer, update UpdateV6) error {
	var command [39]byte
	command[0] = CommandUpdateV6
	command[1] = update.Protocol
	copy(command[2:18], update.LocalAddress[:])
	binary.LittleEndian.PutUint16(command[18:20], update.LocalPort)
	copy(command[20:36], update.RemoteAddress[:])
	binary.LittleEndian.PutUint16(command[36:38], update.RemotePort)
	command[38] = update.Verdict
	return writeCommand(writer, command[:])
}

// SendClearCacheCommand sends a ClearCache command to the kext.
func SendClearCacheCommand(writer io.Writer) error {
	return writeCommand(writer, []byte{CommandClearCache})
}

// SendGetLogsCommand sends a GetLogs command to the kext.
func SendGetLogsCommand(writer io.Writer) error {
	return writeCommand(writer, []byte{CommandGetLogs})
}

// SendGetBandwidthStatsCommand sends a GetBandwidthStats command to the kext.
func SendGetBandwidthStatsCommand(writer io.Writer) error {
	return writeCommand(writer, []byte{CommandBandwidthStats})
}

// SendPrintMemoryStatsCommand sends a PrintMemoryStats command to the kext.
func SendPrintMemoryStatsCommand(writer io.Writer) error {
	return writeCommand(writer, []byte{CommandPrintMemoryStats})
}

// SendCleanEndedConnectionsCommand sends a CleanEndedConnections command to the kext.
func SendCleanEndedConnectionsCommand(writer io.Writer) error {
	return writeCommand(writer, []byte{CommandCleanEndedConnections})
}
