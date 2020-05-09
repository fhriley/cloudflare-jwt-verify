package main

import (
    "context"
    "encoding/binary"
	"fmt"
    "net"
    "net/http"
    "os"

    "github.com/coreos/go-oidc"
)

type LocalIpv4 struct {
    ip   uint32
    mask uint32
}

var (
    allowLocal = getEnv("ALLOW_LOCAL", "") != ""
    address = getEnv("LISTEN_ADDRESS", "127.0.0.1")
    port = getEnv("LISTEN_PORT", "80")
    localIpv4 = []LocalIpv4{
        {0xa000000, 0xff000000},
        {0xac100000, 0xfff00000},
        {0xc0a80000, 0xffff0000},
    }

    // jwt signing keys
    keySet oidc.KeySet
    verifier *oidc.IDTokenVerifier
)

func init() {

	authDomain := getEnv("AUTH_DOMAIN", "")
    if authDomain == "" {
        fmt.Println("ERROR: Please provide the authorization domain you configured on cloudflare. Should be like `https://foo.cloudflareaccess.com`")
        os.Exit(1)
    }

	audienceTag := getEnv("AUDIENCE_TAG", "")
    if audienceTag == "" {
        fmt.Println("ERROR: Please provide the audience tag form your access policy configured on cloudflare.")
        os.Exit(1)
    }

    // configure keyset
    certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", authDomain)
    keySet = oidc.NewRemoteKeySet(context.TODO(), certsURL)
    config := &oidc.Config{
        ClientID: audienceTag,
    }
    verifier = oidc.NewVerifier(authDomain, keySet, config)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func isLocalIpv4(ipv4 string) bool {
	if ipv4 == "" {
		return false
	}

	ipObj := net.ParseIP(ipv4)
	if ipObj == nil {
		return false
	}

	ipObj = ipObj.To4()
	if ipObj == nil {
		return false
	}

	ip := binary.BigEndian.Uint32(ipObj)
	for _, localIp := range localIpv4 {
		if (ip & localIp.mask) == localIp.ip {
			return true
		}
	}

	return false
}

func VerifyToken(writer http.ResponseWriter, request *http.Request) {
	headers := request.Header

	// Make sure that the incoming request has our token header
	//  Could also look in the cookies for CF_AUTHORIZATION
	accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		if allowLocal && isLocalIpv4(request.Header.Get("X-Real-IP")) {
			return
		}
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("No token on the request"))
		return
	}

	// Verify the access token
	ctx := request.Context()
	_, err := verifier.Verify(ctx, accessJWT)
	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
		return
	}
}

func main() {
	http.Handle("/", http.HandlerFunc(VerifyToken))
	http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), nil)
}
