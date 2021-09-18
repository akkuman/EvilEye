package main

import (
	"fmt"
	"gBeaconEye/beaconeye"
	"time"
)

func main() {
	v1 := time.Now()
	evils, err := beaconeye.FindEvil()
	if err != nil {
		panic(err)
	}
	v2 := time.Now()
	fmt.Println(v2.Sub(v1))
	var prev string
	for _, v := range evils {
		if prev == v.Path {
			continue
		}
		fmt.Printf("%s: %s\n", v.Path, v.Arch)
		prev = v.Path
	}
}
