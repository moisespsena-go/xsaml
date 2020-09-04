package samlidp

import (
	"net/http"

	saml "github.com/moisespsena-go/xsaml"
)

type SessionCreationHandler interface {
	Handle(req *saml.IdpAuthnRequest, user User, session *saml.Session) (*saml.Session, error)
}

type SessionCreationHandlerFunc func(req *saml.IdpAuthnRequest, user User, session *saml.Session) (*saml.Session, error)

func (f SessionCreationHandlerFunc) Handle(req *saml.IdpAuthnRequest, user User, session *saml.Session) (*saml.Session, error) {
	return f(req, user, session)
}

type MultipleSessionCreationHandlers []SessionCreationHandler

func (handlers MultipleSessionCreationHandlers) Handle(req *saml.IdpAuthnRequest, user User, session *saml.Session) (*saml.Session, error) {
	var err error
	for _, h := range handlers {
		if session, err = h.Handle(req, user, session); err != nil {
			break
		}
	}
	return session, nil
}

func (handlers *MultipleSessionCreationHandlers) Use(h ...SessionCreationHandler) MultipleSessionCreationHandlers {
	return append(*handlers, h...)
}

// LoginFormHandler is a login form handler ware produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
type LoginFormHandler interface {
	Handle(w http.ResponseWriter, req *saml.IdpAuthnRequest, err error)
}

type LoginFormHandlerFunc func(w http.ResponseWriter, req *saml.IdpAuthnRequest, err error)

func (h LoginFormHandlerFunc) Handle(w http.ResponseWriter, req *saml.IdpAuthnRequest, err error) {
	h(w, req, err)
}

type HttpHandlers struct {
	Login,
	Metadata,
	SSO http.Handler
}