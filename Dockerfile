# -------- Builder --------
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
# 调试友好的静态构建：保留符号、关内联、DWARF不压缩、启用帧指针
ENV GOEXPERIMENT=framepointer
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor \
             -gcflags=all="-N -l" \
             -ldflags="-compressdwarf=false" \
             -o pcapdemo main.go

# -------- Runner (scratch) --------
FROM scratch
WORKDIR /app
# 复制可执行文件
COPY --from=builder /app/pcapdemo /app/pcapdemo
# 如果你需要用“镜像内置的样例 pcap”，保留这一行；否则删掉
COPY pcaps /app/pcaps
# 以 root 运行（scratch 下没有用户管理；如需非 root 可改造）
ENTRYPOINT ["/app/pcapdemo"]