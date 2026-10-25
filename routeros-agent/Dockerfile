FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY routeros-agent/go.mod ./
COPY routeros-agent/*.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/s5m-routeros-agent .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /etc/s5m && addgroup -S s5m && adduser -S -D -H -G s5m s5m
COPY --from=build /out/s5m-routeros-agent /usr/local/bin/s5m-routeros-agent
USER s5m
ENTRYPOINT ["/usr/local/bin/s5m-routeros-agent"]
