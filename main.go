package main

import (
	"fmt"
	"gBeaconEye/beaconeye"
)

func main() {
	evils, err := beaconeye.FindEvil()
	if err != nil {
		panic(err)
	}
	var prev string
	for _, v := range evils {
		if prev == v.Path {
			continue
		}
		fmt.Printf("%s: %s\n", v.Path, v.Arch)
		prev = v.Path
	}
}
