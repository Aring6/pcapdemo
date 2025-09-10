# ---------- 构建阶段 ----------
FROM golang:1.22 AS builder

WORKDIR /app

# 拷贝项目文件（包含 go.mod、go.sum、vendor/、main.go 等）
COPY . .

# 使用 vendor 依赖构建二进制
RUN go build -mod=vendor -o pcapdemo main.go

# ---------- 运行阶段 ----------
FROM debian:bullseye-slim

WORKDIR /app

# 拷贝二进制到运行镜像
COPY --from=builder /app/pcapdemo .

# 可选：把样例 pcap 文件也拷贝进镜像（调试用）
COPY pcaps ./pcaps

# 默认启动程序
CMD ["./pcapdemo"]

