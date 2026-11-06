# SecureProjects container image: the static CLI plus nothing else.
# External tools are not bundled; the native analyzers work out of the box.
# Example:
#   docker run --rm -v "$PWD:/src:ro" -v "$PWD/reports:/reports" secureprojects scan /src -o /reports -f table,json,sarif
FROM golang:1.26-alpine AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/secureprojects/secureprojects/internal/version.Version=${VERSION}" \
    -o /out/secureprojects ./cmd/secureprojects

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secureprojects /usr/local/bin/secureprojects
USER nonroot:nonroot
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/secureprojects"]
CMD ["--help"]
