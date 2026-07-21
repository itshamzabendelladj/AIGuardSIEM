FROM golang:1.22 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /api-gateway ./api/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /api-gateway /usr/local/bin/
EXPOSE 8080 8443
CMD ["api-gateway"]
