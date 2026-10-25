# syntax=docker/dockerfile:1
ARG GO_VERSION=1.23
ARG ALPINE_VERSION=3.21
ARG MIHOMO_VERSION=v1.19.31
# SHA-256 digests published by the official MetaCubeX/mihomo v1.19.31 release.
ARG MIHOMO_AMD64_SHA256=04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc
ARG MIHOMO_ARM64_SHA256=9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS agent-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY s5m-agent/go.mod s5m-agent/go.sum ./
RUN go mod download
COPY s5m-agent/main.go ./main.go
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/s5m-agent .

FROM alpine:${ALPINE_VERSION} AS mihomo-fetch
ARG TARGETARCH
ARG MIHOMO_VERSION
ARG MIHOMO_AMD64_SHA256
ARG MIHOMO_ARM64_SHA256
RUN apk add --no-cache ca-certificates curl gzip
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) asset="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz"; expected_sha256="${MIHOMO_AMD64_SHA256}" ;; \
      arm64) asset="mihomo-linux-arm64-${MIHOMO_VERSION}.gz"; expected_sha256="${MIHOMO_ARM64_SHA256}" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors \
      "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${asset}" -o /tmp/mihomo.gz; \
    echo "${expected_sha256}  /tmp/mihomo.gz" | sha256sum -c -; \
    gzip -dc /tmp/mihomo.gz > /usr/local/bin/mihomo; \
    chmod 0755 /usr/local/bin/mihomo; \
    /usr/local/bin/mihomo -v

FROM alpine:${ALPINE_VERSION} AS runtime
RUN apk add --no-cache ca-certificates tzdata tini \
    && addgroup -S s5m && adduser -S -D -H -G s5m s5m \
    && mkdir -p /data /app
WORKDIR /app
COPY --from=agent-builder /out/s5m-agent /app/s5m-agent
COPY --from=mihomo-fetch /usr/local/bin/mihomo /usr/local/bin/mihomo
COPY s5m-agent/index.html /app/index.html
COPY s5m-agent/entrypoint.sh /entrypoint.sh
COPY s5m-agent/healthcheck.sh /healthcheck.sh
COPY s5m-agent/default-config.yaml /app/default-config.yaml
RUN chmod 0755 /entrypoint.sh /healthcheck.sh
ENV S5M_AGENT_PORT=81 \
    MIHOMO_HOME=/data \
    MIHOMO_API=127.0.0.1:8088
VOLUME ["/data"]
EXPOSE 81 7890 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/healthcheck.sh"]
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
