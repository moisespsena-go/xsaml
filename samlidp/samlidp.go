// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"
	"path"
	"sync"

	saml "github.com/moisespsena-go/xsaml"
	"github.com/moisespsena-go/xsaml/logger"
)

// Options represent the parameters to New() for creating a new IDP server
type Options struct {
	URL                     func(idp *saml.IdentityProvider, r *http.Request, pth ...string) *url.URL
	Key                     crypto.PrivateKey
	Logger                  logger.Interface
	Certificate             *x509.Certificate
	Store                   Store
	Users                   UsersServiceProvider
	Sessions                SessionsStorer
	Services                ServicesProvider
	SessionCreationHandlers MultipleSessionCreationHandlers
	LoginFormHandler        LoginFormHandler
	Setup                   func(srv *Server)
}

// Server represents an IDP server. The server provides the following URLs:
//
//     /metadata     - the SAML metadata
//     /sso          - the SAML endpoint to initiate an authentication flow
//     /login        - prompt for a username and password if no session established
//     /login/:shortcut - kick off an IDP-initiated authentication flow
//     /services     - RESTful interface to Service objects
//     /users        - RESTful interface to UserImpl objects
//     /sessions     - RESTful interface to Session objects
//     /shortcuts    - RESTful interface to Shortcut objects
type Server struct {
	http.Handler
	idpConfigMu             sync.RWMutex // protects calls into the IDP
	logger                  logger.Interface
	serviceProviders        map[string]*saml.EntityDescriptor
	IDP                     *saml.IdentityProvider // the underlying IDP
	Store                   Store                  // the data store
	Users                   UsersServiceProvider
	SessionCreationHandlers MultipleSessionCreationHandlers
	Sessions                SessionsStorer
	LoginFormHandler        LoginFormHandler
	Services                ServicesProvider
}

// New returns a new Server
func New(opts Options) (*Server, error) {
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	s := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		IDP: saml.NewIdentityProvider(&saml.IdentityProvider{
			Key:         opts.Key,
			Logger:      logr,
			Certificate: opts.Certificate,
			URLFunc: func(idp *saml.IdentityProvider, r *http.Request, pth ...string) string {
				return opts.URL(idp, r, pth...).String()
			},
		}),
		logger:                  logr,
		Store:                   opts.Store,
		Users:                   opts.Users,
		Sessions:                opts.Sessions,
		SessionCreationHandlers: opts.SessionCreationHandlers,
		Services:                opts.Services,
		LoginFormHandler:        opts.LoginFormHandler,
	}

	if s.LoginFormHandler == nil {
		s.LoginFormHandler = DefaultLoginFormHandler
	}

	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if opts.Setup != nil {
		opts.Setup(s)
	}

	oldReqSetup := s.IDP.SetupRequestFunc
	s.IDP.SetupRequestFunc = func(idp *saml.IdentityProvider, r *saml.IdpAuthnRequest) (err error) {
		WithSessionCreationHandler(r, func(next SessionCreationHandler) SessionCreationHandler {
			if next == nil {
				next = s.SessionCreationHandlers
			}
			return SessionCreationHandlerFunc(func(req *saml.IdpAuthnRequest, user User, session *saml.Session) (*saml.Session, error) {
				return next.Handle(req, user, session)
			})
		})
		WithLoginFormHandler(r, func(next LoginFormHandler) LoginFormHandler {
			if next == nil {
				next = s.LoginFormHandler
			}
			return LoginFormHandlerFunc(func(w http.ResponseWriter, req *saml.IdpAuthnRequest, err error) {
				next.Handle(w, req, err)
			})
		})
		if oldReqSetup != nil {
			err = oldReqSetup(idp, r)
		}
		return
	}

	return s, nil
}

// InitializeHTTP sets up the HTTP handler for the server. (This function
// is called automatically for you by New, but you may need to call it
// yourself if you don't create the object using New.)
func (s *Server) Mount(handleFunc func(pattern string, handler func(w http.ResponseWriter, r *http.Request)), pth string) {
	pth = path.Clean(pth) + "/"
	handleFunc(pth+s.IDP.Paths.Metadata, s.HTTPMetadataHandle)
	handleFunc(pth+s.IDP.Paths.SSO, s.HTTPSSOHandle)
}

func (s *Server) HttpHandler() http.Handler {
	mux := http.NewServeMux()
	s.Mount(mux.HandleFunc, "/")
	return mux
}

type MuxFuncHandler interface {
}
