package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	devName string = "en0"
	found   bool   = false
)

func main() {
	// Find all network interfaces for package capturing using pcap.FindAllDevs()
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic("error finding network interfaces: %w", err.Error())
	}

	for _, device := range devices {
		if device.Name == devName {
			found = true
			break
		}
	}

	// If the desired device if foubd continue other exit the program
	if !found {
		log.Panic("Error finding network interface: %w", devName)
	}

	// Open the device for capturing using pcap.OpenLive()
	handle, err := pcap.OpenLive(devName, 1060, false, pcap.BlockForever)
	if err != nil {
		log.Panic("Error opening hnadle on the device: %w", err.Error())
	}
	defer handle.Close()

	// Apply BPF filter to the device on this new handle using pcap.SetBPFFilter()
	if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
		log.Panic("Error setting BPF filter: %w", err.Error())
	}
	// Show all the filtered packets received on channel returned from gopacket.NewPacketSource()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				log.Printf("Got a packet with payload: %v", payload)
			}

			//if the bytes in the payload contain and HTTP Post request this will print out all the data that was sent, including the username and password or some other sensitive data
			if bytes.Contains(payload, []byte("POST")) || bytes.Contains(payload, []byte("post")) || bytes.Contains(payload, []byte("USER")) || bytes.Contains(payload, []byte("user")) || bytes.Contains(payload, []byte("PASS")) || bytes.Contains(payload, []byte("pass")) {
				fmt.Println("-------->", string(payload))
				/// printing the credentials
				fmt.Println("")

			}

		} else {
			log.Println("No application layer found in packet")
		}

	}

}
