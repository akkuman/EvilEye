package beaconeye

import (
	"encoding/binary"
	"io"
)

func UintptrListContains(list []uintptr, v uintptr) bool {
	for i := range list {
		if list[i] == v {
			return true
		}
	}
	return false
}

// BytesIndexOf returns the index of the first instance of c in b, or -1 if c is not present in b.
func BytesIndexOf(b []byte, c byte, startIdx int) (ret int) {
	for i := startIdx; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func ReadInt64(r io.Reader) int64 {
	data := make([]byte, 8)
	r.Read(data)
	return int64(binary.LittleEndian.Uint64(data))
}

func ReadInt32(r io.Reader) int32 {
	data := make([]byte, 4)
	r.Read(data)
	return int32(binary.LittleEndian.Uint32(data))
}

func ReadInt16(r io.Reader) int16 {
	data := make([]byte, 2)
	r.Read(data)
	return int16(binary.LittleEndian.Uint16(data))
}
