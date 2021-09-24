# EvilEye

EvilEye is a [BeaconEye](https://github.com/CCob/BeaconEye) implement in Golang. It is used to detect the cobaltstrike beacon from memory and extract some configuration.

# Try & Run

download EvilEye in [releases](https://github.com/akkuman/EvilEye/releases)

```shell
./EvilEye.exe
```

## Screenshot

![](https://raw.githubusercontents.com/akkuman/pic/master/img/2021/09/bf0e1b48ba856c7b539cfcd5a58a738a.png)

# Build

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

func banner() string {
	return `EvilEye by @akkuman(github.com/akkuman)`
}

func main() {
	fmt.Printf("%s\n\n\n", banner())
	v1 := time.Now()
	evilResults := make(chan beaconeye.EvilResult)
	go func() {
		err := beaconeye.FindEvil(evilResults, 4)
		if err != nil {
			panic(err)
		}
	}()
	count := 0
	for v := range evilResults {
		fmt.Printf("%s (%d), Keys Found:True, Configuration Address: 0x%x\n", v.Name, v.Pid, v.Address)
		fmt.Printf("%s\n", v.Extractor.GetConfigText())
		count++
	}
	v2 := time.Now()
	fmt.Printf("The program took %v to find out %d processes\n", v2.Sub(v1), count)
}
```

# TODO

- Extraction configuration from memory(portion done)


# References
- [Windows 10 Nt Heap Exploitation (English version)](https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-english-version)
- [@d1nfinite](https://github.com/d1nfinite) 's PR on BeaconEye: [[Bug Fix] Scan Heap Blocks](https://github.com/CCob/BeaconEye/pull/3)
- [如何正确的 "手撕" Cobalt Strike](https://mp.weixin.qq.com/s/_gSPWVb1b-xuvhU6ynmw0Q)
- [win 10 heap internal & exploitation](https://0x43434343.github.io/win10_internal/)
- [SEGMENT HEAP的简单分析和WINDBG EXTENSION](https://whereisk0shl.top/post/segment_heap_ext)
- [NtApiDotNet repository](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtApiDotNet)
