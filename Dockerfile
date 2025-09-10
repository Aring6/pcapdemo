# -------- Builder --------
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
# 关键：禁用 cgo，构建纯静态二进制（避免 glibc 依赖）
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -trimpath -ldflags="-s -w" -o pcapdemo main.go

# -------- Runner (scratch) --------
FROM scratch
WORKDIR /app
# 复制可执行文件
COPY --from=builder /app/pcapdemo /app/pcapdemo
# 如果你需要用“镜像内置的样例 pcap”，保留这一行；否则删掉
COPY pcaps /app/pcaps
# 以 root 运行（scratch 下没有用户管理；如需非 root 可改造）
ENTRYPOINT ["/app/pcapdemo"]