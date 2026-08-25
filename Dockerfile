# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Keep readable tags for auditability and immutable digests for reproducible
# resolution. Dependabot proposes digest updates for review.
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS web-build
ARG COMMIT=unknown
ENV WITSHIELD_BUILD_ID=${COMMIT}
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY web/ ./
RUN npm run typecheck && npm run test && npm run build:embedded

FROM golang:1.27.0-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 AS go-build
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
# The default keeps the official checksum-verified module path and a direct
# fallback. Builders in restricted networks can override this explicitly, for
# example: --build-arg GOPROXY=https://goproxy.cn,direct. go.sum verification
# remains mandatory either way.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/witshield-controller ./cmd/witshield-controller && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/witshield-agent ./cmd/witshield-agent && \
    mkdir -p /out/data/controller /out/data/agent && \
    chown -R 65532:65532 /out/data

# The binaries are fully static. A scratch runtime avoids a third registry
# dependency and keeps the observer image usable where gcr.io is unavailable.
# Copy only the CA bundle needed for HTTPS Controller/AI connections.
FROM scratch
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="WitShield AI" \
      org.opencontainers.image.description="Open-source agentic security guard for Linux servers" \
      org.opencontainers.image.source="https://github.com/witkitlab/witshield" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=go-build /out/witshield-controller /usr/local/bin/witshield-controller
COPY --from=go-build /out/witshield-agent /usr/local/bin/witshield-agent
COPY --from=go-build --chown=65532:65532 /out/data /data
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=web-build /src/web/out /usr/share/witshield/web
COPY LICENSE /usr/share/licenses/witshield/LICENSE

USER 65532:65532
EXPOSE 8080
ENV WITSHIELD_WEB_DIR=/usr/share/witshield/web
ENTRYPOINT ["/usr/local/bin/witshield-controller"]
CMD ["--listen", "0.0.0.0:8080", "--data-dir", "/data/controller"]
