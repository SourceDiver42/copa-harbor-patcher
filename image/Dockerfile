# Runtime image bundling `copa` plus our own small Go tools (webhook
# receiver, sweep-helper, harbor-report), used for both the CronJob sweep and
# the webhook receiver. No trivy binary is bundled — vulnerability data comes
# from Harbor's own built-in scanner via harbor-report, not a second scan.
#
# `copa` is downloaded as a checksum-verified tagged release binary (not
# built from source) — matches goreleaser's actual archive/checksum naming
# from https://github.com/project-copacetic/copacetic/releases, e.g.
# copa_0.15.0_linux_amd64.tar.gz + copacetic_checksums.txt.
#
# Single-platform (builds for the host's GOOS/GOARCH) to stay compatible with
# the classic `docker build` builder; see README for a BuildKit/buildx
# variant if you need cross-platform images.

ARG GO_VERSION=1.26.8
ARG ALPINE_IMAGE=alpine:3.23
ARG COPA_VERSION=v0.15.0

FROM alpine:3.23 AS copa-fetcher
ARG COPA_VERSION
# TARGETARCH is auto-populated by BuildKit/buildx; defaulted here so a plain
# `docker build` (no buildx) still works for local amd64 development.
ARG TARGETARCH=amd64
RUN apk add --no-cache curl
WORKDIR /out
RUN set -eu; \
    ver="${COPA_VERSION#v}"; \
    arch="${TARGETARCH:-amd64}"; \
    archive="copa_${ver}_linux_${arch}.tar.gz"; \
    base="https://github.com/project-copacetic/copacetic/releases/download/${COPA_VERSION}"; \
    curl -fsSLO "${base}/${archive}"; \
    curl -fsSLO "${base}/copacetic_checksums.txt"; \
    grep " ${archive}\$" copacetic_checksums.txt | sha256sum -c -; \
    tar -xzf "${archive}" copa; \
    rm -f "${archive}" copacetic_checksums.txt

FROM golang:${GO_VERSION}-alpine AS tools-builder
WORKDIR /src/tools
COPY tools/go.mod tools/go.sum ./
RUN go mod download
COPY tools/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/webhook-server ./cmd/webhook-server \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sweep-helper ./cmd/sweep-helper \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/harbor-report ./cmd/harbor-report

FROM ${ALPINE_IMAGE}
RUN apk add --no-cache ca-certificates bash \
    && rm -rf /var/cache/apk/*
COPY --from=copa-fetcher /out/copa /usr/local/bin/copa
COPY --from=tools-builder /out/webhook-server /usr/local/bin/webhook-server
COPY --from=tools-builder /out/sweep-helper /usr/local/bin/sweep-helper
COPY --from=tools-builder /out/harbor-report /usr/local/bin/harbor-report
COPY scripts/sweep.sh /usr/local/bin/sweep.sh
COPY scripts/patch-one.sh /usr/local/bin/patch-one.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/*.sh \
    && addgroup -g 1000 copa && adduser -D -u 1000 -G copa copa
LABEL org.opencontainers.image.title="copa-harbor-patcher" \
      org.opencontainers.image.source="https://github.com/project-copacetic/copacetic" \
      sh.copa-harbor.copa-version="${COPA_VERSION}"
# Non-root by default even outside Kubernetes. CA trust is expected to be
# provided by the cluster (e.g. trust-manager) — this image doesn't manage
# its own trust store.
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
