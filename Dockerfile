# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -o /gateway ./cmd/gateway

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /gateway /gateway

EXPOSE 443 9090

USER nonroot:nonroot

ENTRYPOINT ["/gateway"]
