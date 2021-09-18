package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gBeaconEye/win32"
	"os"
	"reflect"
	"strconv"
	"unsafe"
)

func main() {
	buf := win32.RtlCreateQueryDebugBuffer(0, false)
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	_, err = win32.RtlQueryProcessDebugInformation(win32.HANDLE(pid), win32.ULONG(win32.RTL_QUERY_PROCESS_HEAP_SUMMARY|win32.RTL_QUERY_PROCESS_HEAP_ENTRIES), buf)
	if err != nil {
		panic(err)
	}
	var heapNodeCount int
	if buf.Heaps != nil {
		heapNodeCount = int(buf.Heaps.NumberOfHeaps)
	}
	fmt.Printf("\nheapNodeCount: %d", heapNodeCount)
	heapsStart := buf.Heaps.Heaps
	heapsStartAddr := uintptr(unsafe.Pointer(&heapsStart[0]))
	fmt.Printf("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	for i := 0; i < heapNodeCount; i++ {
		item := win32.RTL_HEAP_INFORMATION{}
		fmt.Printf("\n0x%x", heapsStartAddr)
		heapsStartAddr, err = readToStruct(heapsStartAddr, &item)
		if err != nil {
			panic(err)
		}
		// item := unsafe.Slice(&heapsStart[0], heapNodeCount)[i]
		fmt.Printf("\n Base Address = 0x%.8x", item.BaseAddress)
		fmt.Printf("\n Block count = %d", item.NumberOfEntries)
		fmt.Printf("\n Committed Size= 0x%.8x", item.BytesCommitted)
		fmt.Printf("\n Allocated Size = 0x%.8x", item.BytesAllocated)
		fmt.Printf("\n Flags = 0x%.8x", item.Flags)
		fmt.Println()
	}
}

func main2() {
	src := make([]byte, 500)
	var dst win32.RTL_HEAP_INFORMATION
	err := packBytesToStruct(src, &dst)
	fmt.Println("%#v", dst)
	if err != nil {
		panic(err)
	}
}

func getStructPackLen(dst interface{}) int {
	dstV := reflect.Indirect(reflect.ValueOf(dst))
	numField := dstV.NumField()
	totalSize := 0
	for i := 0; i < numField; i++ {
		fieldV := dstV.Field(i)
		size := fieldV.Type().Size()
		totalSize += int(size)
	}
	return totalSize
}

func packBytesToStruct(src []byte, dst interface{}) (err error) {
	dstV := reflect.ValueOf(dst)
	if dstV.Kind() != reflect.Ptr {
		return fmt.Errorf("dst is not address")
	}
	dstV = dstV.Elem()
	numField := dstV.NumField()
	totalSize := 0
	for i := 0; i < numField; i++ {
		fieldV := dstV.Field(i)
		size := fieldV.Type().Size()
		totalSize += int(size)
	}
	if len(src) < totalSize {
		return fmt.Errorf("the length of src less than the length of dst")
	}
	buf := bytes.NewBuffer(src)
	for i := 0; i < numField; i++ {
		fieldV := dstV.Field(i)
		size := fieldV.Type().Size()
		data_ := make([]byte, size)
		binary.Read(buf, binary.LittleEndian, data_)
		if !fieldV.CanAddr() {
			return fmt.Errorf("field %s is not addressable", dstV.Type().Field(i).Name)
		}
		for idx, v := range data_ {
			v_ := *(*[1]byte)(unsafe.Pointer(fieldV.UnsafeAddr() + uintptr(idx)))
			v_[0] = v
		}

	}
	return nil
}

func packReadToStruct(startAddr uintptr, dst interface{}) (nextAddr uintptr, err error) {
	dstV := reflect.ValueOf(dst)
	if dstV.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("dst is not address")
	}
	dstV = dstV.Elem()
	numField := dstV.NumField()
	for i := 0; i < numField; i++ {
		fieldV := dstV.Field(i)
		size := fieldV.Type().Size()
		if !fieldV.CanAddr() {
			return 0, fmt.Errorf("field %s is not addressable", dstV.Type().Field(i).Name)
		}
		for j := 0; j < int(size); j++ {
			// startAddr_ := uintptr(unsafe.Pointer(startAddr))
			nextAddr = startAddr + uintptr(j) + 1
			v := (*(*[1]byte)(unsafe.Pointer(startAddr + uintptr(j))))[0]
			(*(*[1]byte)(unsafe.Pointer(fieldV.UnsafeAddr() + uintptr(j))))[0] = v
		}
	}
	return
}

func readToStruct(startAddr uintptr, dst interface{}) (nextAddr uintptr, err error) {
	dstV := reflect.ValueOf(dst)
	if dstV.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("dst is not address")
	}
	dstV = dstV.Elem()
	totalSize := int(dstV.Type().Size())
	for i := 0; i < totalSize; i++ {
		v := (*(*[1]byte)(unsafe.Pointer(startAddr + uintptr(i))))[0]
		(*(*[1]byte)(unsafe.Pointer(dstV.UnsafeAddr() + uintptr(i))))[0] = v
		nextAddr = startAddr + uintptr(i) + 1
	}
	// numField := dstV.NumField()
	// for i := 0; i < numField; i++ {
	// 	fieldV := dstV.Field(i)
	// 	size := fieldV.Type().Size()
	// 	if !fieldV.CanAddr() {
	// 		return 0, fmt.Errorf("field %s is not addressable", dstV.Type().Field(i).Name)
	// 	}
	// 	for j := 0; j < int(size); j++ {
	// 		// startAddr_ := uintptr(unsafe.Pointer(startAddr))
	// 		nextAddr = startAddr + uintptr(j)
	// 		v := (*(*[1]byte)(unsafe.Pointer(startAddr + uintptr(j))))[0]
	// 		(*(*[1]byte)(unsafe.Pointer(fieldV.UnsafeAddr() + uintptr(j))))[0] = v
	// 	}
	// }
	return
}
