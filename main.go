package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/checkers"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery/identchecker"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"github.com/gorilla/mux"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"
	"gopkg.in/errgo.v1"
	"gopkg.in/yaml.v2"
)

const (
	defaultDischargeExpiry = 10 * time.Second
)

// helloService implements a "target service", representing
// an arbitrary web service that wants to delegate authorization
// to third parties.
func newHelloService(endpoint, authEndpoint string) (http.Handler, error) {
	key, err := bakery.GenerateKey()
	if err != nil {
		return nil, err
	}
	pkLocator := httpbakery.NewThirdPartyLocator(nil, nil)
	pkLocator.AllowInsecure()
	b := identchecker.NewBakery(identchecker.BakeryParams{
		Key:      key,
		Location: endpoint,
		Locator:  pkLocator,
		Checker:  httpbakery.NewChecker(),
		Authorizer: authorizer{
			thirdPartyLocation: authEndpoint,
		},
	})
	mux := mux.NewRouter()
	srv := &helloServiceHandler{
		checker:      b.Checker,
		oven:         &httpbakery.Oven{Oven: b.Oven},
		authEndpoint: authEndpoint,
	}
	mux.Handle("/hello/{username}", srv.auth(srv.serveHello))
	return mux, nil
}

type helloServiceHandler struct {
	checker      *identchecker.Checker
	oven         *httpbakery.Oven
	authEndpoint string
}

func (srv *helloServiceHandler) serveHello(w http.ResponseWriter, req *http.Request, username string) {
	fmt.Fprintf(w, "Hello %s", username)
}

// auth wraps the given handler with a handler that provides
// authorization by inspecting the HTTP request
// to decide what authorization is required.
func (srv *helloServiceHandler) auth(h func(w http.ResponseWriter, req *http.Request, identity string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := httpbakery.ContextWithRequest(context.TODO(), req)

		ops, err := opsForRequest(req)
		if err != nil {
			fail(w, http.StatusInternalServerError, "%v", err)
			return
		}
		authChecker := srv.checker.Auth(httpbakery.RequestMacaroons(req)...)
		authInfo, err := authChecker.Allow(ctx, ops...)
		if err != nil {
			httpbakery.WriteError(ctx, w, srv.oven.Error(ctx, req, err))
			return
		}
		username := ""
		for _, cond := range authInfo.Conditions() {
			if !strings.Contains(cond, "declared") {
				continue
			}
			tokens := strings.Split(cond, " ")
			if len(tokens) != 3 {
				continue
			}
			switch tokens[1] {
			case "username":
				if username == "" {
					username = tokens[2]
				}
			case "external-username":
				username = tokens[2]
			default:
			}
		}
		h(w, req, username)
	})
}

// opsForRequest returns the required operations
// implied by the given HTTP request.
func opsForRequest(req *http.Request) ([]bakery.Op, error) {
	pathVars := mux.Vars(req)
	username := pathVars["username"]

	return []bakery.Op{{
		Entity: username,
		Action: "hello",
	}}, nil
}

func fail(w http.ResponseWriter, code int, msg string, args ...interface{}) {
	http.Error(w, fmt.Sprintf(msg, args...), code)
}

type authorizer struct {
	thirdPartyLocation string
}

// Authorize implements bakery.Authorizer.Authorize by
// allowing anyone to do anything if a third party
// approves it.
func (a authorizer) Authorize(ctx context.Context, id identchecker.Identity, ops []bakery.Op) (allowed []bool, caveats []checkers.Caveat, err error) {
	allowed = make([]bool, len(ops))
	caveats = make([]checkers.Caveat, len(ops))
	for i, op := range ops {
		allowed[i] = true
		caveats[i] = checkers.Caveat{
			Location:  a.thirdPartyLocation,
			Condition: fmt.Sprintf("is-user %s", op.Entity),
		}
	}
	return
}

//
//
//  USER SERVICE
//
//

// userService implements an authorization service,
// that can discharge third-party caveats added
// to other macaroons.
func userService(endpoint string, key *bakery.KeyPair) (http.Handler, error) {
	d := httpbakery.NewDischarger(httpbakery.DischargerParams{
		Checker: httpbakery.ThirdPartyCaveatCheckerFunc(thirdPartyChecker),
		Key:     bakery.MustGenerateKey(),
	})

	mux := http.NewServeMux()
	d.AddMuxHandlers(mux, "/")
	return mux, nil
}

var dischargeCount = 0

// thirdPartyChecker is used to check third party caveats added by other
// services. The HTTP request is that of the client - it is attempting
// to gather a discharge macaroon.
//
// Note how this function can return additional first- and third-party
// caveats which will be added to the original macaroon's caveats.
func thirdPartyChecker(ctx context.Context, req *http.Request, info *bakery.ThirdPartyCaveatInfo, token *httpbakery.DischargeToken) ([]checkers.Caveat, error) {
	caveatTokens := strings.Split(string(info.Condition), " ")
	if len(caveatTokens) != 2 {
		zapctx.Error(ctx, "caveat token length incorrect", zap.Int("length", len(caveatTokens)))
		return nil, checkers.ErrCaveatNotRecognized
	}
	caveatCondition := caveatTokens[0]
	userString := caveatTokens[1]

	if caveatCondition != "is-user" {
		zapctx.Error(ctx, "unknown third party caveat", zap.String("condition", caveatCondition))
		return nil, checkers.ErrCaveatNotRecognized
	}

	user := readUsername()
	if user.Username != userString {
		zapctx.Debug(ctx, "macaroon dishcharge denied", zap.String("user", userString))
		return nil, httpbakery.ErrPermissionDenied
	}

	if dischargeCount == 0 {
		dischargeCount += 1
		return []checkers.Caveat{
			checkers.DeclaredCaveat("username", user.Username),
			checkers.TimeBeforeCaveat(time.Now().Add(defaultDischargeExpiry)),
			httpbakery.SameClientIPAddrCaveat(req),
		}, nil
	}

	return []checkers.Caveat{
		checkers.DeclaredCaveat("username", user.Username),
		checkers.DeclaredCaveat("external-username", user.ExternalUsername),
		checkers.TimeBeforeCaveat(time.Now().Add(defaultDischargeExpiry)),
		httpbakery.SameClientIPAddrCaveat(req),
	}, nil
}

func serve(newHandler func(string) (http.Handler, error)) (endpointURL string, err error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", fmt.Errorf("cannot listen: %v", err)
	}
	endpointURL = "http://" + listener.Addr().String()
	handler, err := newHandler(endpointURL)
	if err != nil {
		return "", fmt.Errorf("cannot start handler: %v", err)
	}
	go http.Serve(listener, handler)
	return endpointURL, nil
}

func mustServe(newHandler func(string) (http.Handler, error)) (endpointURL string) {
	endpoint, err := serve(newHandler)
	if err != nil {
		log.Fatalf("cannot serve: %v", err)
	}
	return endpoint
}

func newClient() *httpbakery.Client {
	c := httpbakery.NewClient()
	c.AddInteractor(httpbakery.WebBrowserInteractor{})
	return c
}

// client represents a client of the target service.
// In this simple example, it just tries a GET
// request, which will fail unless the client
// has the required authorization.
func clientRequest(client *httpbakery.Client, serverEndpoint string) (string, error) {
	// The Do function implements the mechanics
	// of actually gathering discharge macaroons
	// when required, and retrying the request
	// when necessary.
	req, err := http.NewRequest("GET", serverEndpoint, nil)
	if err != nil {
		return "", errgo.Notef(err, "cannot make new HTTP request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errgo.NoteMask(err, "GET failed", errgo.Any)
	}
	defer resp.Body.Close()
	// TODO(rog) unmarshal error
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("cannot read response: %v", err)
	}
	return string(data), nil
}

type user struct {
	Username         string `yaml:"username"`
	ExternalUsername string `yaml:"external-username"`
}

// readUsername reds the username from user.yaml.
func readUsername() user {
	var userData user
	data, err := os.ReadFile("./user.yaml")
	if err != nil {
		return userData
	}

	err = yaml.Unmarshal(data, &userData)
	if err != nil {
		return userData
	}
	return userData
}

//
//
// MAIN
//
//

func main() {
	key, err := bakery.GenerateKey()
	if err != nil {
		log.Fatalf("cannot generate auth service key pair: %v", err)
	}
	authEndpoint := mustServe(func(endpoint string) (http.Handler, error) {
		return userService(endpoint, key)
	})
	serverEndpoint := mustServe(func(endpoint string) (http.Handler, error) {
		return newHelloService(endpoint, authEndpoint)
	})

	resp, err := clientRequest(newClient(), serverEndpoint+"/hello/ivan")
	if err != nil {
		fmt.Printf("client failed: %v", err)
	} else {
		fmt.Printf("client success: %q\n", resp)
	}

	resp, err = clientRequest(newClient(), serverEndpoint+"/hello/ivan")
	if err != nil {
		fmt.Printf("client failed: %v", err)
	} else {
		fmt.Printf("client success: %q\n", resp)
	}
}
