// Packge nns provides a net.Conn abstraction to communicate on a negotiated stream
// Ref : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/3e77f3ac-db7e-4c76-95de-911dd280947b
package nns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

type AuthPacket struct {
	MessageType  MessageType
	MajorVersion uint8
	MinorVersion uint8
	Size         uint16
	Payload      []byte
}

type MessageType uint8

const (
	HandshakeInProgress MessageType = 0x16
	HandshakeError      MessageType = 0x15
	HandshakeDone       MessageType = 0x14
)

// UnmarshalAuthPacket Reads the next NSS authentication packet from a reader interface
func UnmarshalAuthPacket(connReader io.Reader) (packet AuthPacket, err error) {
	if err = binary.Read(connReader, binary.BigEndian, &packet.MessageType); err != nil {
		return packet, err
	}
	if err = binary.Read(connReader, binary.BigEndian, &packet.MajorVersion); err != nil {
		return packet, err
	}
	if err = binary.Read(connReader, binary.BigEndian, &packet.MinorVersion); err != nil {
		return packet, err
	}
	// High / low ... fuck you MS , just say BigEndian
	if err = binary.Read(connReader, binary.BigEndian, &packet.Size); err != nil {
		return packet, err
	}
	writer := bytes.NewBuffer([]byte{})
	if n, err := io.CopyN(writer, connReader, int64(packet.Size)); err != nil || n != int64(packet.Size) {
		return packet, errors.New("ctx read error")
	}
	packet.Payload = writer.Bytes()
	return packet, nil
}

// WriteTo writes an NNS authentication packet to a writer interface
func (vp *AuthPacket) WriteTo(writer io.Writer) error {
	vp.Size = uint16(len(vp.Payload))
	vp.MajorVersion = 0x01
	vp.MinorVersion = 0x00
	if err := binary.Write(writer, binary.BigEndian, vp.MessageType); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, vp.MajorVersion); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, vp.MinorVersion); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, vp.Size); err != nil {
		return err
	}
	if _, err := writer.Write(vp.Payload); err != nil {
		return err
	}
	return nil
}

// ErrNotNNSPacket Is returned when the packet is not an NNS packet
var ErrNotNNSPacket = errors.New("not an NNS packet")
