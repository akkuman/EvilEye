package win32

import (
	"fmt"
	"unsafe"
)

type (
	DWORD   uint32
	HANDLE  uintptr
	BOOL    int
	PVOID   uintptr
	LPVOID  uintptr
	SIZE_T  uintptr
	LPCVOID uintptr
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       PVOID
	AllocationBase    PVOID
	AllocationProtect DWORD
	RegionSize        SIZE_T
	State             DWORD
	Protect           DWORD
	Type              DWORD
}

var (
	TRUE  BOOL = 1
	FALSE BOOL = 0
)

const PROCESS_ALL_ACCESS = DWORD(0x1F0FFF)

func VirtualQueryEx(hProcess HANDLE, lpAddress LPCVOID) (MEMORY_BASIC_INFORMATION, error) {
	mbi := MEMORY_BASIC_INFORMATION{}
	ret := _VirtualQueryEx(hProcess, lpAddress, uintptr(unsafe.Pointer(&mbi)), SIZE_T(uintptr(unsafe.Sizeof(mbi))))
	if ret == 0 {
		return mbi, fmt.Errorf("call VirtualQueryEx error")
	}
	return mbi, nil
}

func ReadProcessMemory(hProcess HANDLE, lpBaseAddress LPCVOID, lpBuffer []byte) (int, error) {
	const bufSize = 4096
	var tmpBuf [bufSize]byte
	lpBufferLen := len(lpBuffer)
	nSize := SIZE_T(bufSize)
	lpNumberOfBytesRead := SIZE_T(0)
	mod := lpBufferLen % bufSize
	var readIdx int
	for readIdx = 0; readIdx < lpBufferLen; readIdx += int(nSize) {
		if lpBufferLen-readIdx < bufSize {
			nSize = SIZE_T(mod)
		}
		ret := _ReadProcessMemory(
			hProcess,
			lpBaseAddress+LPCVOID(readIdx),
			LPVOID(uintptr(unsafe.Pointer(&tmpBuf))),
			nSize,
			&lpNumberOfBytesRead,
		)

		if ret == 0 {
			return 0, fmt.Errorf("call ReadProcessMemory error")
		}

		if nSize != lpNumberOfBytesRead {
			fmt.Printf("%v != %v", nSize, lpNumberOfBytesRead)
		}

		copy(lpBuffer[readIdx:], tmpBuf[:nSize])
	}
	return readIdx, nil
}

//sys OpenProcess(dwDesiredAccess DWORD, bInheritHandle BOOL, dwProcessId DWORD) (handle HANDLE) = kernel32.OpenProcess
//sys _VirtualQueryEx(hProcess HANDLE, lpAddress LPCVOID, lpBuffer uintptr, dwLength SIZE_T) (size SIZE_T) = kernel32.VirtualQueryEx
//sys _ReadProcessMemory(hProcess HANDLE, lpBaseAddress LPCVOID, lpBuffer LPVOID, nSize SIZE_T, lpNumberOfBytesRead *SIZE_T) (ret BOOL) = kernel32.ReadProcessMemory
