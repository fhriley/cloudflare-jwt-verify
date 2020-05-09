FROM golang:1.14-alpine

WORKDIR /go/src/cloudflare-jwt-verify
COPY . .
RUN go get -d -v ./...
RUN go install -v ./...

EXPOSE 80

CMD ["cloudflare-jwt-verify"]
