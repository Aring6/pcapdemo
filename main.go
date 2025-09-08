package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	// 可以是单文件，也可以是目录
	path := "pcaps"

	info, err := os.Stat(path)
	if err != nil {
		panic(err)
	}

	if info.IsDir() {
		filepath.WalkDir(path, func(file string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if !d.IsDir() && filepath.Ext(file) == ".pcap" {
				parsePcap(file)
			}
			return nil
		})
	} else {
		parsePcap(path)
	}
}

func parsePcap(file string) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("无法打开文件 %s: %v\n", file, err)
		return
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Printf("无法读取 pcap %s: %v\n", file, err)
		return
	}

	var total int
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		total++

		// 走解析逻辑
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.NoCopy)
		_ = packet.Layer(layers.LayerTypeIPv4)
		_ = packet.Layer(layers.LayerTypeIPv6)
		_ = packet.Layer(layers.LayerTypeTCP)
		_ = packet.Layer(layers.LayerTypeUDP)
	}

	fmt.Printf("文件 %s 解析完成，总包数: %d\n", file, total)
}
