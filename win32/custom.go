package win32

import "encoding/binary"

type MemoryInfo struct {
	MEMORY_BASIC_INFORMATION
	IsExecutable bool
	NoAccess     bool
}

// NTHeapSignature is a segmentheap signature
// ref: https://whereisk0shl.top/post/segment_heap_ext
// Microsoft enables a new heap management mechanism Low Fragmentation Heap (LFH) in Windows 10,
// Windows uses NT Heap in R3, but in specific processes, such as lsass.exe, svchost.exe, etc, Windows use Segment Heap
// Regarding Segment Heap and NT Heap distinguish between the Signature member variable of its head structure,
// Signature is saved in the Heap Header + 0x10 position.
// When Signature is 0xddeeddee, the heap is Segment Heap, and when Signature is 0xffeeffee, the heap is NT Heap.
var NTHeapSignature DWORD = 0xffeeffee

func QueryMemoryInfo(hProcess HANDLE, lpAddress LPCVOID) (memInfo MemoryInfo, err error) {
	memInfo.MEMORY_BASIC_INFORMATION, err = VirtualQueryEx(hProcess, lpAddress)
	if err != nil {
		return
	}
	memInfo.IsExecutable = memInfo.MEMORY_BASIC_INFORMATION.Protect == DWORD(ExecuteRead) ||
		memInfo.MEMORY_BASIC_INFORMATION.Protect == DWORD(ExecuteReadWrite)
	memInfo.NoAccess = memInfo.MEMORY_BASIC_INFORMATION.Protect&NoAccess == NoAccess
	return
}

// IsNTHeap determine if the heap is a NT Heap
func IsNTHeap(hProcess HANDLE, heapBase uintptr) (isNTHeap bool, err error) {
	var sigBytes []byte
	addr := uintptr(heapBase + 0x10)
	sigBytes, err = NtReadVirtualMemory(hProcess, PVOID(addr), 4)
	if err != nil {
		return
	}
	sig := binary.LittleEndian.Uint32(sigBytes)
	isNTHeap = DWORD(sig) == NTHeapSignature
	return
}
