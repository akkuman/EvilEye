package beaconeye

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
