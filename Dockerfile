FROM golang:1.22.2 as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server

FROM scratch

COPY --from=builder /app/server /

ENTRYPOINT ["/server"]
