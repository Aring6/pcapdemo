package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// 在 K8s 中挂载 hostPath:/data/pcaps -> /app/pcaps 时，保持这个路径
const inputPath = "pcaps"

// 无文件时避免空转刷满 CPU（解析过程中不休眠）
const idleSleep = 300 * time.Millisecond

// 每个包重复解析次数：调大=更吃 CPU
const repeatPerPacket = 3

// 心跳打印间隔
const heartbeatInterval = 30 * time.Second

func main() {
	var cycles uint64
	lastPrint := time.Now()
	for {
		files, err := listPcapFiles(inputPath)
		if err != nil || len(files) == 0 {
			time.Sleep(idleSleep)
			continue
		}
		for _, f := range files {
			parsePcapFileSlow(f)
		}
		// 不休眠：完成一轮立刻开始下一轮，持续占用 CPU

		if time.Since(lastPrint) >= heartbeatInterval {
			fmt.Printf("[heartbeat] %s running... cycles=%d\n",
				time.Now().Format("2006-01-02 15:04:05"), cycles)
			lastPrint = time.Now()
		}
	}
}

// 列出目录/单文件中的 .pcap
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
	out := make([]string, 0, 256)
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

// 更吃 CPU 的解析：拷贝+全量解码 + 重复解析
func parsePcapFileSlow(file string) {
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

		// 对每个包重复解析多次，放大 CPU 消耗
		for i := 0; i < repeatPerPacket; i++ {
			// 使用 Default（非 NoCopy），会拷贝数据并触发更完整解析
			pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)

			// 访问常见层，促使解码路径被执行
			_ = pkt.Layer(layers.LayerTypeIPv4)
			_ = pkt.Layer(layers.LayerTypeIPv6)
			_ = pkt.Layer(layers.LayerTypeTCP)
			_ = pkt.Layer(layers.LayerTypeUDP)

			// 迭代所有已解码层，进一步增加工作量
			for range pkt.Layers() {
				// no-op：纯粹走一遍层列表，制造遍历开销
			}

			// 如果存在应用层，读取一下 payload 长度以形成有效访问（避免被编译器过度优化）
			if app := pkt.ApplicationLayer(); app != nil {
				_ = len(app.Payload())
			}
		}
	}
}