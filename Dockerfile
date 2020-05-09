FROM golang:1.14-alpine

WORKDIR /go/src/cloudflare-jwt-verify
COPY . .
RUN go get -d -v ./...
RUN go install -v ./...

CMD ["cloudflare-jwt-verify"]
