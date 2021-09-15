package win32

import (
	"fmt"
	"unsafe"
)

type (
	DWORD            uint32
	HANDLE           uintptr
	BOOL             int
	PVOID            uintptr
	PBOOL            uintptr
	LPVOID           uintptr
	SIZE_T           uintptr
	LPCVOID          uintptr
	ProcessInfoClass uint32
	ULONG            uintptr
	PULONG           uintptr
	NTSTATUS         int32
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

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessId uintptr
}

var (
	TRUE  BOOL = 1
	FALSE BOOL = 0

	ProcessBasicInformation   ProcessInfoClass = 0
	ProcessDebugPort          ProcessInfoClass = 7
	ProcessWow64Information   ProcessInfoClass = 26
	ProcessImageFileName      ProcessInfoClass = 27
	ProcessBreakOnTermination ProcessInfoClass = 29

	SizeOfProcessBasicInformation = unsafe.Sizeof(PROCESS_BASIC_INFORMATION{})

	STATUS_PENDING      DWORD = 0x00000103
	STATUS_PARTIAL_COPY DWORD = 0x8000000D

	ExecuteReadWrite DWORD = 0x40
	ExecuteRead      DWORD = 0x20
	NoAccess         DWORD = 0x01
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

func ReadProcessMemoryOnce(hProcess HANDLE, lpBaseAddress LPCVOID, size int64) (buffer []byte, err error) {
	buffer = make([]byte, size)
	nSize := SIZE_T(size)
	lpNumberOfBytesRead := SIZE_T(0)
	ret := _ReadProcessMemory(
		hProcess,
		lpBaseAddress,
		LPVOID(unsafe.Pointer(&buffer[0])),
		nSize,
		&lpNumberOfBytesRead,
	)
	fmt.Printf("debug: ret: %x\n", ret)
	if ret == 0 {
		return buffer, fmt.Errorf("call ReadProcessMemory error")
	}

	return
}

func NtReadVirtualMemory(hProcess HANDLE, baseAddress PVOID, size int64) (buffer []byte, err error) {
	buffer = make([]byte, size)
	nSize := ULONG(size)
	NumberOfBytesRead := ULONG(0)
	status := _NtReadVirtualMemory(
		hProcess,
		baseAddress,
		PVOID(unsafe.Pointer(&buffer[0])),
		nSize,
		PULONG(unsafe.Pointer(&NumberOfBytesRead)),
	)

	if status < 0 {
		if DWORD(status) != STATUS_PARTIAL_COPY {
			return buffer, fmt.Errorf("call NtReadVirtualMemory error")
		}
		if NumberOfBytesRead != 0 {
			buffer = buffer[:NumberOfBytesRead]
		}
	}

	return
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

func NtQueryInformationProcess(ProcessHandle HANDLE, ProcessInformationClass ProcessInfoClass, ProcessInformation unsafe.Pointer, ProcessInformationLength ULONG, ReturnLength *ULONG) (status NTSTATUS, err error) {
	ret := _NtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		LPVOID(unsafe.Pointer(ProcessInformation)),
		ProcessInformationLength,
		PULONG(unsafe.Pointer(ReturnLength)),
	)
	status = NTSTATUS(ret)
	if status < 0 {
		err = fmt.Errorf("call NtQueryInformationProcess failed, err code: %x", uint32(status))
	}
	return
}

func IsWow64Process(hProcess HANDLE) (isWow64 bool) {
	var Wow64Process int = 1
	ret := _IsWow64Process(hProcess, PBOOL(unsafe.Pointer(&Wow64Process)))
	if ret != 0 {
		return true
	}
	return false
}

//sys OpenProcess(dwDesiredAccess DWORD, bInheritHandle BOOL, dwProcessId DWORD) (handle HANDLE) = kernel32.OpenProcess
//sys _VirtualQueryEx(hProcess HANDLE, lpAddress LPCVOID, lpBuffer uintptr, dwLength SIZE_T) (size SIZE_T) = kernel32.VirtualQueryEx
//sys _ReadProcessMemory(hProcess HANDLE, lpBaseAddress LPCVOID, lpBuffer LPVOID, nSize SIZE_T, lpNumberOfBytesRead *SIZE_T) (ret BOOL) = kernel32.ReadProcessMemory
//sys _NtQueryInformationProcess(ProcessHandle HANDLE, ProcessInformationClass ProcessInfoClass, ProcessInformation LPVOID, ProcessInformationLength ULONG, ReturnLength PULONG) (status NTSTATUS) = ntdll.NtQueryInformationProcess
//sys _IsWow64Process(hProcess HANDLE, Wow64Process PBOOL) (ret BOOL) = kernel32.IsWow64Process
//sys _NtReadVirtualMemory(hProcess HANDLE, BaseAddress PVOID, Buffer PVOID, BufferLength ULONG, ReturnLength PULONG) (status NTSTATUS) = ntdll.NtReadVirtualMemory
