# syntax=docker/dockerfile:1
ARG GO_VERSION=1.23
ARG ALPINE_VERSION=3.21
ARG MIHOMO_VERSION=v1.19.31

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS agent-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY s5m-agent/main.go ./s5m-agent/main.go
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/s5m-agent ./s5m-agent/main.go

FROM alpine:${ALPINE_VERSION} AS mihomo-fetch
ARG TARGETARCH
ARG MIHOMO_VERSION
RUN apk add --no-cache ca-certificates curl gzip
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) asset="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz" ;; \
      arm64) asset="mihomo-linux-arm64-${MIHOMO_VERSION}.gz" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${asset}" -o /tmp/mihomo.gz; \
    gzip -dc /tmp/mihomo.gz > /usr/local/bin/mihomo; \
    chmod 0755 /usr/local/bin/mihomo; \
    /usr/local/bin/mihomo -v

FROM alpine:${ALPINE_VERSION} AS runtime
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S s5m && adduser -S -D -H -G s5m s5m \
    && mkdir -p /data/s5m-next /opt/s5m-next/s5m-agent
WORKDIR /app
COPY --from=agent-builder /out/s5m-agent /app/s5m-agent
COPY --from=mihomo-fetch /usr/local/bin/mihomo /usr/local/bin/mihomo
COPY s5m-agent/index.html /opt/s5m-next/s5m-agent/index.html
COPY s5m-agent/entrypoint.sh /entrypoint.sh
COPY s5m-agent/default-config.yaml /opt/s5m/default-config.yaml
RUN chmod 0755 /entrypoint.sh
ENV S5M_AGENT_PORT=81 \
    MIHOMO_HOME=/data/s5m-next \
    MIHOMO_API=127.0.0.1:8088
VOLUME ["/data"]
EXPOSE 81 7890 8088
ENTRYPOINT ["/entrypoint.sh"]
