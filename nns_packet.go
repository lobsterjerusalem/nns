package nns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
)

// NNSPacket is a raw NNS packet before any decryption
type DataPacket struct {
	Size    uint32
	Payload []byte
}

// Bytes corrects the size and returns an NNS packet as bytes
func (dp DataPacket) Bytes() []byte {
	buffer := bytes.NewBuffer([]byte{})
	dp.WriteTo(buffer)
	return buffer.Bytes()
}

// Bytes corrects the size and returns an NNS packet as bytes
func (dp DataPacket) WriteTo(writer io.Writer) error {
	dp.Size = uint32(len(dp.Payload))
	err := binary.Write(writer, binary.LittleEndian, dp.Size)
	if err != nil {
		return err
	}
	n, err := writer.Write(dp.Payload)
	if err != nil {
		return err
	}
	if n != len(dp.Payload) {
		return errors.New("failed to write full data packet")
	}
	return nil
}

// UnmarshalNNSPacket reads an NNS packet
func UnmarshalNNSPacket(reader io.Reader) (packet DataPacket, err error) {
	err = binary.Read(reader, binary.LittleEndian, &packet.Size)
	if err != nil {
		return packet, err
	}
	log.Printf("NNS packet size : %s", packet.Size)
	buffer := bytes.NewBuffer([]byte{})
	_, err = io.CopyN(buffer, reader, int64(packet.Size))
	if err != nil {
		return packet, err
	}
	packet.Payload = buffer.Bytes()
	return packet, nil
}
