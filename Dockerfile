FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /server ./cmd/server/main.go

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=builder /server /server

EXPOSE 8080

CMD ["/server"]
