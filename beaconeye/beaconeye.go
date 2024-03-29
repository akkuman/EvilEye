package beaconeye

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/akkuman/EvilEye/win32"

	gops "github.com/mitchellh/go-ps"
)

const ARBITRARY = 0x100
const NOP = -1

type MatchResult struct {
	Addr uint64
}

type EvilResult struct {
	Pid       int
	Name      string
	Address   uint64
	Extractor ConfigExtractor
}

var SystemInfo win32.SystemInfo

func init() {
	var err error
	SystemInfo, err = win32.GetNativeSystemInfo()
	if err != nil {
		panic(err)
	}
}

type sSearchIn struct {
	procScan   *ProcessScan
	matchArray []uint16
	nextArray  []int16
	memInfo    win32.MemoryInfo
	process    gops.Process
}

var onceCloseSearchOut sync.Once

type sSearchOut struct {
	procScan *ProcessScan
	process  gops.Process
	addr     uintptr
}

type ProcessScan struct {
	// the handle of the process
	Handle win32.HANDLE
	// Wow64Info
	// If this value is nonzero, the process is running in a WOW64 environment;
	// otherwise, if the value is equal to zero, the process is not running in a WOW64 environment.
	Wow64Info uintptr
	// Is64Bit whether the process is 64 bit process
	Is64Bit bool
	// PebAddress the base address of peb of the process
	PebAddress uintptr
	// NumberOfHeaps Number of the processes
	NumberOfHeaps uint32
	// ProcHeapsArrayAddr is the first address of a heap array, and each array element is pointer which pointer to heap.
	ProcHeapsArrayAddr uintptr
	// heaps is the array, and each array element is pointer which pointer to heap.
	Heaps []uintptr
}

func NewProcessScan(pid win32.DWORD) (processScan *ProcessScan, err error) {
	processScan = new(ProcessScan)
	// get handle of process
	processScan.Handle = win32.OpenProcess(win32.PROCESS_ALL_ACCESS, win32.FALSE, pid)
	if processScan.Handle == 0 {
		err = fmt.Errorf("cannot OpenProcess with pid %d", pid)
		return
	}
	processScan.Wow64Info, err = GetProcWow64Info(processScan.Handle)
	if err != nil {
		return
	}
	processScan.Is64Bit = processScan.Wow64Info == 0
	// get peb base address of process
	processScan.PebAddress, err = GetProcPebAddr(processScan.Handle)
	if err != nil {
		return
	}
	// get heap num and heap array address and all heaps of process
	err = processScan.initHeapsInfo()
	return
}

func (p *ProcessScan) pointerSize() uintptr {
	if p.Is64Bit {
		return 8
	}
	return 4
}

func (p *ProcessScan) getOffsetSegmentListEntry() (offset uintptr) {
	if p.Is64Bit {
		offset = uintptr(0x18)
	} else {
		offset = uintptr(0x10)
	}
	return
}

func (p *ProcessScan) getOffsetSegmentList() (offset uintptr) {
	if p.Is64Bit {
		offset = uintptr(0x120)
	} else {
		offset = uintptr(0xa4)
	}
	return
}

func (p *ProcessScan) getAllHeapSegments(heap uintptr) (segs []uintptr, err error) {
	var trace []uintptr
	segs = append(segs, heap)
	offsetSegmentList := p.getOffsetSegmentList()
	offsetSegmentListEntry := p.getOffsetSegmentListEntry()
	segmentListEntryBlink := heap
	for {
		segmentListEntryBlink, err = GetProcUintptr(p.Handle, segmentListEntryBlink+offsetSegmentListEntry+p.pointerSize(), p.Is64Bit)
		if err != nil {
			return segs, err
		}
		if UintptrListContains(trace, segmentListEntryBlink) {
			break
		}
		trace = append(trace, segmentListEntryBlink)
		segmentAddr := segmentListEntryBlink - p.getOffsetSegmentListEntry()
		if segmentListEntryBlink != heap+offsetSegmentList &&
			segmentListEntryBlink != heap+offsetSegmentListEntry &&
			!UintptrListContains(segs, segmentAddr) {
			segs = append(segs, segmentAddr)
		}
		segmentListEntryBlink = segmentAddr
	}
	return segs, nil
}

// getAllHeapBlocks get all blocks from a heap segment
// TOOO: speed up according to the pagesize
func (p *ProcessScan) getAllHeapBlocks(seg uintptr, xorkey uint16) (blocks []uintptr, err error) {
	firstEntry, err := GetProcUintptr(p.Handle, seg+uintptr(0x40), p.Is64Bit)
	if err != nil {
		return blocks, err
	}
	lastValidEntry, err := GetProcUintptr(p.Handle, seg+uintptr(0x48), p.Is64Bit)
	if err != nil {
		return blocks, err
	}
	startAddr := firstEntry
	for {
		blocks = append(blocks, startAddr)
		// get size of current block
		size, err := GetProcUint16(p.Handle, startAddr+uintptr(0x08))
		if err != nil {
			return blocks, err
		}
		size = (size ^ xorkey) << 4
		// Dealing with dead loops in some special cases where size == 0
		if size == 0 {
			break
		}
		startAddr = startAddr + uintptr(size)
		if startAddr > lastValidEntry {
			break
		}
	}
	return blocks, err
}

// getAllRegion get all region from a heap segment according to FirstEntry and LastValidEntry
func (p *ProcessScan) getAllRegion(seg uintptr) (regions []uintptr, err error) {
	firstEntry, err := GetProcUintptr(p.Handle, seg+uintptr(0x40), p.Is64Bit)
	if err != nil {
		return regions, err
	}
	lastValidEntry, err := GetProcUintptr(p.Handle, seg+uintptr(0x48), p.Is64Bit)
	if err != nil {
		return regions, err
	}
	startAddr := firstEntry
	for {
		memInfo, err := win32.QueryMemoryInfo(p.Handle, win32.LPCVOID(startAddr))
		if err != nil {
			fmt.Printf("error: %v\n", err)
			continue
		}
		regions = append(regions, uintptr(memInfo.BaseAddress))
		startAddr = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
		if startAddr > lastValidEntry {
			break
		}
	}
	return
}

func (p *ProcessScan) initHeapsInfo() (err error) {
	var numHeapsAddr uintptr
	var heapArrayAddr uintptr

	pebBaseAddr := p.PebAddress
	if p.Is64Bit {
		numHeapsAddr = pebBaseAddr + uintptr(0xE8)
		heapArrayAddr = pebBaseAddr + uintptr(0xF0)
	} else {
		numHeapsAddr = pebBaseAddr + uintptr(0x88)
		heapArrayAddr = pebBaseAddr + uintptr(0x90)
	}
	p.NumberOfHeaps, err = GetProcUint32(p.Handle, numHeapsAddr)
	if err != nil {
		return
	}
	p.ProcHeapsArrayAddr, err = GetProcUintptr(p.Handle, heapArrayAddr, p.Is64Bit)
	if err != nil {
		return
	}

	for idx := 0; uint32(idx) < p.NumberOfHeaps; idx++ {
		var heap uintptr
		heap, err = GetProcUintptr(p.Handle, p.ProcHeapsArrayAddr+uintptr(idx)*p.pointerSize(), p.Is64Bit)
		if err != nil {
			return
		}
		// ref: https://github.com/CCob/BeaconEye/commit/808e594d7e0ec37d70c3dd7cca8dde8d31ae27b9#diff-3bf0890f572241d122dd631cf90b569bd1914ab2d1a709314ce7cbfe588dd8fcR64
		// you can use `dt _heap` in windbg to view memory structure (https://0x43434343.github.io/win10_internal/)
		isNTHeap, err := win32.IsNTHeap(p.Handle, heap)
		if err != nil {
			return err
		}
		// TODO: support 32bit process
		if isNTHeap {
			// get all heap segment from a heap
			segs, err := p.getAllHeapSegments(heap)
			if err != nil {
				return err
			}
			if p.Is64Bit {
				// get all block from a heap segment
				for _, segment := range segs {
					p.addHeapPageBase(segment)
					regions, err := p.getAllRegion(segment)
					if err != nil {
						return err
					}
					for _, region := range regions {
						p.addHeapPageBase(region)
					}
				}
			} else {
				for _, segment := range segs {
					p.addHeapPageBase(segment)
				}
			}
		} else {
			p.addHeapPageBase(heap)
		}
	}
	return nil
}

// addHeapPageBase add a page baseaddr of a address to the heaps of ProcessScan
func (p *ProcessScan) addHeapPageBase(heap uintptr) bool {
	pageSize := SystemInfo.PageSize
	baseAddr := (heap / uintptr(pageSize)) * uintptr(pageSize)
	return p.addHeap(baseAddr)
}

// addHeap Add a uintptr to the heaps of ProcessScan
func (p *ProcessScan) addHeap(heap uintptr) bool {
	if !UintptrListContains(p.Heaps, heap) {
		p.Heaps = append(p.Heaps, heap)
		return true
	}
	return false
}

func (p *ProcessScan) SearchMemory(matchArray []uint16, nextArray []int16, process gops.Process, searchIn chan sSearchIn) {
	var memoryInfos []win32.MemoryInfo
	// streamlining memory block information
	tmp := p.Heaps[:]
	for {
		if len(tmp) == 0 {
			break
		}
		start := uintptr(0)
		end := uintptr(0)
		var needDel []uintptr
		for _, heap := range tmp {
			memInfo, err := win32.QueryMemoryInfo(p.Handle, win32.LPCVOID(heap))
			if err != nil {
				needDel = append(needDel, heap)
				fmt.Printf("error: %v\n", err)
				continue
			}
			start = uintptr(memInfo.BaseAddress)
			end = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
			memoryInfos = append(memoryInfos, memInfo)
			break
		}
		tmp_ := tmp[:]
		tmp = []uintptr{}
		// remove addr which need to be deleted or in previous [start, end] for next cycle
		for _, heap := range tmp_ {
			if !(UintptrListContains(needDel, heap) || (heap >= start && heap < end)) {
				tmp = append(tmp, heap)
			}
		}
	}
	// search match
	for _, memInfo := range memoryInfos {
		if memInfo.NoAccess {
			continue
		}
		searchIn <- sSearchIn{
			procScan:   p,
			matchArray: matchArray,
			nextArray:  nextArray,
			memInfo:    memInfo,
			process:    process,
		}
	}
}

func initMultiThreadSearchMemoryBlock(threadNum int, searchIn chan sSearchIn, searchOut chan sSearchOut) {
	for i := 0; i < threadNum; i++ {
		go func() {
			for item := range searchIn {
				var resultArray []MatchResult
				if err := SearchMemoryBlock(item.procScan.Handle, item.matchArray, uint64(item.memInfo.BaseAddress), int64(item.memInfo.RegionSize), item.nextArray, &resultArray); err != nil {
					fmt.Printf("SearchMemoryBlock error: %v\n", err)
					continue
				}
				for j := range resultArray {
					searchOut <- sSearchOut{
						procScan: item.procScan,
						process:  item.process,
						addr:     uintptr(resultArray[j].Addr),
					}
				}
			}
			onceCloseSearchOut.Do(func() {
				close(searchOut)
			})
		}()
	}
}

func GetMatchArrayAndNext(rule string) (matchArray []uint16, nextArray []int16, err error) {
	matchArray, err = GetMatchArray(rule)
	if err != nil {
		return
	}
	nextArray = GetNext(matchArray)
	return
}

func FindEvil(evilResults chan EvilResult, threadNum int) (err error) {
	var processes []gops.Process
	processes, err = GetProcesses()
	if err != nil {
		return
	}
	rule64 := "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00"
	rule32 := "00 00 00 00 00 00 00 00 01 00 00 00 ?? 00 00 00 01 00 00 00 ?? ?? 00 00 02 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? 00 00"
	matchArray64, nextArray64, err := GetMatchArrayAndNext(rule64)
	if err != nil {
		return
	}
	matchArray32, nextArray32, err := GetMatchArrayAndNext(rule32)
	if err != nil {
		return
	}
	searchIn := make(chan sSearchIn, 100)
	searchOut := make(chan sSearchOut, 100)
	initMultiThreadSearchMemoryBlock(threadNum, searchIn, searchOut)
	go handleItemFromSearchOut(searchOut, evilResults)
	for _, process := range processes {
		// if the process is itslef, then skip
		if os.Getpid() == process.Pid() {
			continue
		}
		processScan, err := NewProcessScan(win32.DWORD(process.Pid()))
		if err != nil {
			fmt.Printf("init process info error: %v\n", err)
			continue
		}
		nextArray := nextArray32
		matchArray := matchArray32
		if processScan.Is64Bit {
			nextArray = nextArray64
			matchArray = matchArray64
		}
		processScan.SearchMemory(matchArray, nextArray, process, searchIn)
	}
	close(searchIn)
	return
}

func handleItemFromSearchOut(searchOut chan sSearchOut, evilResults chan EvilResult) {
	for o := range searchOut {

		configStart := uintptr(o.addr)
		configBytes, err := win32.NtReadVirtualMemory(o.procScan.Handle, win32.PVOID(configStart), int64(o.procScan.pointerSize())*0x100)
		if err != nil {
			fmt.Printf("NtReadVirtualMemory error: %v", err)
			continue
		}
		extractor, err := NewConfigExtractor(configStart, configBytes, *o.procScan)
		if err != nil {
			fmt.Printf("NewConfigExtractor error: %v", err)
			continue
		}
		evilResults <- EvilResult{
			Pid:       o.process.Pid(),
			Name:      o.process.Executable(),
			Extractor: *extractor,
			Address:   uint64(o.addr),
		}
	}
	close(evilResults)
}

func SearchMemoryBlock(hProcess win32.HANDLE, matchArray []uint16, startAddr uint64, size int64, next []int16, pResultArray *[]MatchResult) (err error) {
	var memBuf []byte
	memBuf, err = win32.NtReadVirtualMemory(hProcess, win32.PVOID(startAddr), size)
	size = int64(len(memBuf))
	if err != nil {
		err = fmt.Errorf("%v: %v", err, syscall.GetLastError())
		return
	}

	// sunday algorithm implement
	i := 0      // 父串index
	j := 0      // 字串index
	offset := 0 // 下次匹配的偏移（基于起始位置0）

	for int64(offset) < size {
		// 将父串index设置到偏移量，字串index设置到0
		i = offset
		j = 0
		// 判断匹配
		for j < len(matchArray) && int64(i) < size {
			if matchArray[j] == uint16(memBuf[i]) || int(matchArray[j]) == ARBITRARY {
				i++
				j++
			} else {
				break
			}
		}

		// 如果一直到最后一位，则代表匹配成功
		if j == len(matchArray) {
			*pResultArray = append(*pResultArray, MatchResult{
				Addr: startAddr + uint64(offset),
			})
		}

		// 移至子串在父串对应位置的末尾，如果超出长度则没有匹配到
		if int64(offset+len(matchArray)) >= size {
			return
		}

		// 获取父串中字串末尾所在位置字符，将子串中和该位置相等的字符对齐
		// 得出字串需要移动多少位
		valueAtMIdx := memBuf[offset+len(matchArray)]
		idxInSub := next[valueAtMIdx]
		if idxInSub == NOP { // 可能是匹配不到，或者可以匹配到 ?? 符号
			offset = offset + (len(matchArray) - int(next[ARBITRARY])) // 如果字串存在 ?? 号，则下次匹配移动到该位置开始匹配，否则移动到末尾，即 m = m + 字串长度 + 1
		} else {
			offset = offset + (len(matchArray) - int(idxInSub))
		}
	}
	return
}

// GetMatchArray get []uint16 from string
func GetMatchArray(matchStr string) ([]uint16, error) {
	codes := strings.Split(matchStr, " ")
	result := make([]uint16, len(codes))
	for i, c := range codes {
		if c == "??" {
			result[i] = ARBITRARY
		} else {
			bs, err := hex.DecodeString(c)
			if err != nil {
				return nil, err
			}
			result[i] = uint16(bs[0])
		}
	}
	return result, nil
}

func GetNext(matchArray []uint16) []int16 {
	//特征码（字节集）的每个字节的范围在0-255（0-FF）之间，256用来表示问号，到260是为了防止越界
	next := make([]int16, 260)
	for i := 0; i < len(next); i++ {
		next[i] = NOP
	}
	for i := 0; i < len(matchArray); i++ {
		next[matchArray[i]] = int16(i)
	}
	return next
}

func GetProcPebAddr(hProcess win32.HANDLE) (PebAddress uintptr, err error) {
	var basicInfo win32.PROCESS_BASIC_INFORMATION
	var retLen win32.ULONG
	var wow64Ret uintptr
	wow64Ret, err = GetProcWow64Info(hProcess)
	if err != nil {
		return
	}
	if wow64Ret != 0 {
		PebAddress = wow64Ret
		return
	}
	_, err = win32.NtQueryInformationProcess(
		hProcess,
		win32.ProcessBasicInformation,
		unsafe.Pointer(&basicInfo),
		win32.ULONG(win32.SizeOfProcessBasicInformation),
		&retLen,
	)
	if err != nil {
		err = fmt.Errorf("get peb addr error: %v", err)
		return
	}
	PebAddress = basicInfo.PebBaseAddress
	return
}

func GetProcUint32(hProcess win32.HANDLE, addr uintptr) (num uint32, err error) {
	var numBytes []byte
	numBytes, err = win32.NtReadVirtualMemory(hProcess, win32.PVOID(addr), 4)
	if err != nil {
		return
	}
	num = binary.LittleEndian.Uint32(numBytes)
	return
}

func GetProcUint16(hProcess win32.HANDLE, addr uintptr) (num uint16, err error) {
	var numBytes []byte
	numBytes, err = win32.NtReadVirtualMemory(hProcess, win32.PVOID(addr), 2)
	if err != nil {
		return
	}
	num = binary.LittleEndian.Uint16(numBytes)
	return
}

func GetProcByte(hProcess win32.HANDLE, addr uintptr) (res byte, err error) {
	var numBytes []byte
	numBytes, err = win32.NtReadVirtualMemory(hProcess, win32.PVOID(addr), 1)
	if err != nil {
		return
	}
	res = numBytes[0]
	return
}

func GetProcUintptr(hProcess win32.HANDLE, addr uintptr, is64Bit bool) (ptr uintptr, err error) {
	if is64Bit {
		var ptr_ []byte
		ptr_, err = win32.NtReadVirtualMemory(hProcess, win32.PVOID(addr), 8)
		if err != nil {
			return
		}
		ptr = uintptr(binary.LittleEndian.Uint64(ptr_))
	} else {
		var ptr_ []byte
		ptr_, err = win32.NtReadVirtualMemory(hProcess, win32.PVOID(addr), 4)
		if err != nil {
			return
		}
		ptr = uintptr(binary.LittleEndian.Uint32(ptr_))
	}
	return
}

func GetProcWow64Info(hProcess win32.HANDLE) (ret uintptr, err error) {
	var ulongWow64 win32.ULONG
	var retLen win32.ULONG
	_, err = win32.NtQueryInformationProcess(
		hProcess,
		win32.ProcessWow64Information,
		unsafe.Pointer(&ulongWow64),
		win32.ULONG(unsafe.Sizeof(ulongWow64)),
		&retLen,
	)
	if err != nil {
		err = fmt.Errorf("get isWow64 error: %v", err)
		return
	}
	ret = uintptr(ulongWow64)
	return
}
