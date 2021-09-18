# EvilEye

EvilEye is a [BeaconEye](https://github.com/CCob/BeaconEye) implement in Golang.

# Try & Run

```shell
go install github.com/akkuman/EvilEye
```

# As a package to use

```golang
package main

import (
	"fmt"
	"time"

	"github.com/akkuman/EvilEye/beaconeye"
)

func main() {
	v1 := time.Now()
	evilResults := make(chan beaconeye.EvilResult)
	go func() {
		err := beaconeye.FindEvil(evilResults)
		if err != nil {
			panic(err)
		}
	}()
	for v := range evilResults {
		fmt.Printf("%s: %x\n", v.Name, v.Match)
	}
	v2 := time.Now()
	fmt.Printf("The program took %v to run\n", v2.Sub(v1))
}

```


# References
- [Windows 10 Nt Heap Exploitation (English version)](https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-english-version)
- [@d1nfinite](https://github.com/d1nfinite) 's PR on BeaconEye: [[Bug Fix] Scan Heap Blocks](https://github.com/CCob/BeaconEye/pull/3)
- [如何正确的 "手撕" Cobalt Strike](https://mp.weixin.qq.com/s/_gSPWVb1b-xuvhU6ynmw0Q)
- [win 10 heap internal & exploitation](https://0x43434343.github.io/win10_internal/)
- [SEGMENT HEAP的简单分析和WINDBG EXTENSION](https://whereisk0shl.top/post/segment_heap_ext)
- [NtApiDotNet repository](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtApiDotNet)
