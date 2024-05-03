FROM golang:1.22

LABEL org.opencontainers.image.source https://github.com/illfaku/go-auth

WORKDIR /go/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go install

EXPOSE 80

ENTRYPOINT ["app"]
