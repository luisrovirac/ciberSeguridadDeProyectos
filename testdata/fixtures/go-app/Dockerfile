FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
HEALTHCHECK NONE
ENTRYPOINT ["/app"]
