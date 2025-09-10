# -------- Builder --------
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
# 关键：禁用 cgo，生成纯静态二进制
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -trimpath -ldflags="-s -w" -o pcapdemo main.go

# -------- Runner (no glibc) --------
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --chown=nonroot:nonroot --from=builder /app/pcapdemo .
# 如果你不用 volumes，需要把样例 pcap 打进镜像；否则这一行可以删
COPY --chown=nonroot:nonroot pcaps ./pcaps
USER nonroot
ENTRYPOINT ["/app/pcapdemo"]