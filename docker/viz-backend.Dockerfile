FROM golang:1.22 AS builder
WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /viz-backend ./viz/backend/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /viz-backend /usr/local/bin/
EXPOSE 8051
CMD ["viz-backend"]
