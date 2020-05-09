FROM golang:1.14.2

WORKDIR /go/src/github.com/fhriley/cloudflare-jwt-verify
COPY . .
# Static build required so that we can safely copy the binary over.
RUN go install github.com/fhriley/cloudflare-jwt-verify

ENTRYPOINT ["cloudflare-jwt-verify"]
