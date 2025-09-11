package main

import (
	"bufio"
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

// 每个包重复解析次数：调大=更吃 CPU（优化后默认 1）
const repeatPerPacket = 1

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
			// 使用优化后的解析路径
			parsePcapFileFast(f)
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

// 高效解析：大缓冲顺序读 + 选择性解码 + 复用对象/切片，尽量减少分配与 GC
func parsePcapFileFast(file string) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()

	// 用较大的 bufio.Reader 降低 read 调用次数与系统调用开销（根据介质/吞吐可再调大）
	const readBufSize = 1 << 20 // 1MiB
	br := bufio.NewReaderSize(f, readBufSize)

	r, err := pcapgo.NewReader(br)
	if err != nil {
		return
	}

	// 仅注册必要的协议层，避免不必要解码工作
	var (
		eth layers.Ethernet
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		udp layers.UDP
	)

	// 使用 DecodingLayerParser：复用层对象，避免 NewPacket 的拷贝与一次性对象
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &tcp, &udp,
	)
	// 对未知/不支持的层跳过，而不是报错
	parser.IgnoreUnsupported = true

	// 复用 decoded layers 容器，避免每包分配
	decoded := make([]gopacket.LayerType, 0, 16)

	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			return // EOF 或错误：结束本文件
		}

		for i := 0; i < repeatPerPacket; i++ {
			decoded = decoded[:0]
			// 注意：DecodingLayerParser 不拷贝 data，避免不必要分配与 memclr
			if err := parser.DecodeLayers(data, &decoded); err != nil {
				// 常见情况是遇到未知层/截断包，可忽略以走快路径
				// 如果需要调试，可在这里按需统计
			}

			// 仅在需要时访问已解码层字段；这里演示“触达即止”，避免层遍历带来的额外开销
			// 例如：统计 IP/TCP/UDP 的计数或某些字段
			// if contains(decoded, layers.LayerTypeIPv4) { _ = ip4.Protocol }
			// if contains(decoded, layers.LayerTypeTCP)  { _ = tcp.SrcPort }

			// 如确实需要应用层 payload，可在 TCP/UDP 上自行取出 data[offset:]
			// 以避免 NewPacket 的 applicationLayer 分配与遍历。
		}
	}
}

// 小工具：判断是否包含某层（如需访问字段时使用）
func contains(s []gopacket.LayerType, t gopacket.LayerType) bool {
	for _, x := range s {
		if x == t {
			return true
		}
	}
	return false
}
