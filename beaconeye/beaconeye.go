package beaconeye

import (
	"encoding/hex"
	"gBeaconEye/win32"
	"os"
	"strings"

	gops "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

const BLOCKMAXSIZE = 409600
const ARBITRARY = 0x100
const NOP = -1

type MatchResult struct {
	Addr uint64
}

type EvilResult struct {
	Arch string
	Path string
	Addr uint64
}

func FindEvil() (evilResults []EvilResult, err error) {
	var processes []gops.Process
	processes, err = gops.Processes()
	if err != nil {
		return
	}
	for _, process := range processes {
		// 如果是当前运行进程则跳过
		if os.Getpid() == process.Pid() {
			continue
		}
		handle := win32.OpenProcess(win32.PROCESS_ALL_ACCESS, win32.FALSE, win32.DWORD(process.Pid()))
		searchEvil(handle, "4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03", 0x410000, 0xFFFFFFFF, &evilResults, process, "x64-1")
		searchEvil(handle, "8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2", 0x410000, 0xFFFFFFFF, &evilResults, process, "x86-2")
		searchEvil(handle, "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00", 0x410000, 0xFFFFFFFF, &evilResults, process, "x64-3")
		searchEvil(handle, "00 00 00 00 00 00 00 00 01 00 00 00 ?? 00 00 00 01 00 00 00 ?? ?? 00 00 02 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? 00 00", 0x410000, 0xFFFFFFFF, &evilResults, process, "x86-4")
	}
	return
}

func searchEvil(handle win32.HANDLE, matchStr string, startAddr, endAddr uint64, pResults *[]EvilResult, process gops.Process, arch string) {
	var resultArray []MatchResult
	SearchMemory(handle, matchStr, startAddr, endAddr, &resultArray)
	for _, r := range resultArray {
		*pResults = append(*pResults, EvilResult{
			Arch: arch,
			Path: process.Executable(),
			Addr: r.Addr,
		})
	}
}

func SearchMemoryBlock(hProcess win32.HANDLE, matchArray []uint16, startAddr uint64, size int64, next []int16, pResultArray *[]MatchResult) (err error) {
	memBuf := make([]byte, size)
	win32.ReadProcessMemory(hProcess, win32.LPCVOID(startAddr), memBuf)

	// sunday 算法
	i := 0      // 父串index
	j := 0      // 字串index
	offset := 0 // 下次匹配的偏移（基于起始位置0）

	for int64(offset) < size {
		// 将父串index设置到偏移量，字串index设置到0
		i = offset
		j = 0
		// 判断匹配
		for i < len(matchArray) && int64(j) < size {
			if matchArray[j] == uint16(memBuf[i]) || int(matchArray[j]) == ARBITRARY {
				i++
				j++
			} else {
				break
			}
		}

		// 如果一直到最后一位，则代表匹配成功
		if i == len(matchArray) {
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

func SearchMemory(handle win32.HANDLE, matchStr string, startAddr, endAddr uint64, pResultArray *[]MatchResult) (err error) {
	matchArray, err := GetMatchArray(matchStr)
	if err != nil {
		return err
	}
	next := GetNext(matchArray)
	for {
		mbi, err := win32.VirtualQueryEx(handle, win32.LPCVOID(startAddr))
		if err != nil {
			break
		}
		if mbi.Protect == windows.PAGE_READWRITE || mbi.Protect == windows.PAGE_EXECUTE_READWRITE {
			i := 0
			BlockSize := int64(mbi.RegionSize)
			for BlockSize > BLOCKMAXSIZE {
				if err = SearchMemoryBlock(handle, matchArray, startAddr+uint64(BLOCKMAXSIZE*i), BLOCKMAXSIZE, next, pResultArray); err != nil {
					return err
				}
				BlockSize -= BLOCKMAXSIZE
				i++
			}
			if err = SearchMemoryBlock(handle, matchArray, startAddr+uint64(BLOCKMAXSIZE*i), BlockSize, next, pResultArray); err != nil {
				return err
			}
		}
		startAddr += uint64(mbi.RegionSize)
		if endAddr != 0 && startAddr > endAddr {
			return nil
		}
	}
	return nil
}
