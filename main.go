package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// 写死输入路径：可填目录或单个文件。
// 在 K8s 里挂载 hostPath:/data/pcaps -> /app/pcaps 的话，建议用 "/app/pcaps"
const inputPath = "pcaps"

// 空闲时的短暂休眠，避免空转刷满 CPU（解析过程中不休眠）
const idleSleep = 500 * time.Millisecond

// 轮询间隔：一轮跑完所有文件后立刻开始下一轮（保持持续负载）
const loopSleep = 0 * time.Millisecond

func main() {
	for {
		files, err := listPcapFiles(inputPath)
		if err != nil {
			time.Sleep(idleSleep)
			continue
		}
		if len(files) == 0 {
			time.Sleep(idleSleep)
			continue
		}
		for _, f := range files {
			parsePcapFile(f)
		}
		if loopSleep > 0 {
			time.Sleep(loopSleep)
		}
	}
}

// 列出所有 .pcap（支持目录/单文件）
func listPcapFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if filepath.Ext(path) == ".pcap" {
			return []string{path}, nil
		}
		return nil, os.ErrInvalid
	}
	out := make([]string, 0, 128)
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && filepath.Ext(p) == ".pcap" {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// 只做解析，不打印、不统计
func parsePcapFile(file string) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return
	}
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			return // EOF 或错误：结束本文件
		}
		_ = ci
		pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.NoCopy)
		_ = pkt.Layer(layers.LayerTypeIPv4)
		_ = pkt.Layer(layers.LayerTypeIPv6)
		_ = pkt.Layer(layers.LayerTypeTCP)
		_ = pkt.Layer(layers.LayerTypeUDP)
	}
}