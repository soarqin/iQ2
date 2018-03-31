package main

import (
	"fmt"
	_ "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	devs, _ := pcap.FindAllDevs()
	for idx, dev := range devs {
		for _, addr := range dev.Addresses {
			if !addr.IP.IsGlobalUnicast() {
				continue
			}
			if ip4 := addr.IP.To4(); ip4 != nil {
				fmt.Printf("%v %v %v\n", idx, dev.Name, ip4)
				break
			}
		}
	}
}
