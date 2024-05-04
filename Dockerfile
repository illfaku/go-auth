FROM golang:1.22.2

RUN mkdir /app

COPY . /app

WORKDIR /app

RUN go build -o server .

EXPOSE 80

ENTRYPOINT ["/app/server"]
