package beaconeye

func UintptrListContains(list []uintptr, v uintptr) bool {
	for i := range list {
		if list[i] == v {
			return true
		}
	}
	return false
}
