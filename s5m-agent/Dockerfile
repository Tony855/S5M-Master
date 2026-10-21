FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY main.go .
RUN go build -o /s5m-agent main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /s5m-agent /app/s5m-agent
COPY index.html /app/index.html
EXPOSE 80
CMD ["/app/s5m-agent"]
