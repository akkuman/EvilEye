package beaconeye

import (
	"fmt"
	"gBeaconEye/win32"
	"unsafe"

	gops "github.com/mitchellh/go-ps"
)

func GetProcesses() (needScanProcesses []gops.Process, err error) {
	var processes []gops.Process
	processes, err = gops.Processes()
	if err != nil {
		return
	}

	for _, process := range processes {
		var basicInfo win32.PROCESS_BASIC_INFORMATION
		var retLen uintptr
		hProcess := win32.OpenProcess(win32.PROCESS_ALL_ACCESS, win32.FALSE, win32.DWORD(process.Pid()))
		if hProcess == 0 {
			continue
		}
		_, err = win32.NtQueryInformationProcess(
			hProcess,
			win32.ProcessBasicInformation,
			unsafe.Pointer(&basicInfo),
			win32.SizeOfProcessBasicInformation,
			&retLen,
		)
		if err != nil {
			err = fmt.Errorf("NtQueryInformationProcess error: %v", err)
			continue
		}
		if basicInfo.ExitStatus == uintptr(win32.STATUS_PENDING) {
			needScanProcesses = append(needScanProcesses, process)
		}
	}
	return
}
