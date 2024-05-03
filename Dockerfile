FROM alpine

LABEL org.opencontainers.image.source https://github.com/illfaku/go-auth

COPY app .

EXPOSE 80

ENTRYPOINT ["/app"]
