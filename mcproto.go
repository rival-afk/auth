package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"syscall"
)

// Minecraft protocol helpers (Server List Ping) + statfs.

func putVarInt(b *bytes.Buffer, v int) {
	u := uint32(v)
	for {
		if u&^0x7F == 0 {
			b.WriteByte(byte(u))
			return
		}
		b.WriteByte(byte(u&0x7F | 0x80))
		u >>= 7
	}
}

func readVarInt(r *bufio.Reader) (int, error) {
	var result uint32
	numread := 0
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= uint32(b&0x7F) << (7 * uint(numread))
		numread++
		if b&0x80 == 0 {
			break
		}
		if numread > 5 {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return int(int32(result)), nil
}

func putString(b *bytes.Buffer, s string) {
	putVarInt(b, len(s))
	b.WriteString(s)
}

func readString(r *bufio.Reader) (string, error) {
	n, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	if n < 0 || n > 2*1024*1024 {
		return "", io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func writePacket(c net.Conn, payload []byte) error {
	var p bytes.Buffer
	putVarInt(&p, len(payload))
	p.Write(payload)
	_, err := c.Write(p.Bytes())
	return err
}

// fsBytes returns total and available bytes for the filesystem at path.
func fsBytes(path string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	b := uint64(st.Bsize)
	return st.Blocks * b, st.Bavail * b, nil
}
