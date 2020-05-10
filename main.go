package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc"
)

type LocalIpv4 struct {
	ip   uint32
	mask uint32
}

var (
	allowLocal       = getEnv("ALLOW_LOCAL", "") != ""
	address          = getEnv("LISTEN_ADDRESS", "0.0.0.0")
	port             = getEnv("LISTEN_PORT", "80")
	authEmailHeader  = getEnv("AUTH_EMAIL_HEADER", "")
	authUserIdHeader = getEnv("AUTH_USER_ID_HEADER", "")
	localIpv4        = []LocalIpv4{
		{0xa000000, 0xff000000},
		{0xac100000, 0xfff00000},
		{0xc0a80000, 0xffff0000},
	}

	addAuthHeader bool
	keySet        oidc.KeySet
	verifier      *oidc.IDTokenVerifier
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
	})
	log.SetOutput(os.Stdout)

	addAuthHeader = authEmailHeader != "" || authUserIdHeader != ""

	level, err := log.ParseLevel(getEnv("LOG_LEVEL", "warning"))
	if err == nil {
		log.SetLevel(level)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	authDomain := getEnv("AUTH_DOMAIN", "")
	if authDomain == "" {
		log.Fatal("Please provide the authorization domain you configured on cloudflare. Should " +
			"be like `https://foo.cloudflareaccess.com`")
	}

	audienceTag := getEnv("AUDIENCE_TAG", "")
	if audienceTag == "" {
		log.Fatal("Please provide the audience tag form your access policy configured on cloudflare.")
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
	if log.IsLevelEnabled(log.DebugLevel) {
		data, err := httputil.DumpRequest(request, false)
		if err == nil {
			log.Debug(string(data))
		} else {
			log.Errorf("DumpRequest failed: %s", err.Error())
		}
	}

	headers := request.Header

	// Make sure that the incoming request has our token header
	//  Could also look in the cookies for CF_AUTHORIZATION
	accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		if allowLocal {
			real_ip := request.Header.Get("X-Real-IP")
			if isLocalIpv4(real_ip) {
				log.Debugf("Got local IP %s, allowing access", real_ip)
				return
			}
		}
		log.Debug("No token, denying access")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("No token on the request"))
		return
	}

	// Verify the access token
	ctx := request.Context()
	idToken, err := verifier.Verify(ctx, accessJWT)
	if err != nil {
		log.Debug("Token verification failed, denying access")
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
		return
	}

	log.Debug("Token verified, access allowed")

	if addAuthHeader || log.IsLevelEnabled(log.DebugLevel) {
		var claims struct {
			Email  string `json:"email"`
			UserId string `json:"sub"`
		}

		err := idToken.Claims(&claims)
		if err == nil {
			log.WithFields(log.Fields{
				"Email":  claims.Email,
				"UserId": claims.UserId,
			}).Debug()
			if authEmailHeader != "" {
				log.Debugf("%s: %s", authEmailHeader, claims.Email)
				writer.Header().Set(authEmailHeader, claims.Email)
			}
			if authUserIdHeader != "" {
				log.Debugf("%s: %s", authUserIdHeader, claims.UserId)
				writer.Header().Set(authUserIdHeader, claims.UserId)
			}
		} else {
			log.Errorf("Getting claims failed: %s", err.Error())
		}
	}
}

func main() {
	http.Handle("/", http.HandlerFunc(VerifyToken))

	listen := fmt.Sprintf("%s:%s", address, port)
	log.Infof("Listening on %s", listen)
	http.ListenAndServe(listen, nil)
}
