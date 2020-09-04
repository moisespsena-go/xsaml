package samlidp

import (
	"context"
	"net/http"
	"time"

	saml "github.com/moisespsena-go/xsaml"
)

var sessionMaxAge = time.Hour

type key uint8

const (
	KeySessionCreationHandler key = iota
	KeyLoginFormCallback
)

func WithSessionCreationHandler(req *saml.IdpAuthnRequest, handler ...func(next SessionCreationHandler) SessionCreationHandler) {
	h := GetSessionCreationHandler(req)
	for _, handler := range handler {
		h = handler(h)
	}
	req.Context = context.WithValue(req.Context, KeySessionCreationHandler, h)
}

func GetSessionCreationHandler(req *saml.IdpAuthnRequest) SessionCreationHandler {
	if v := req.Context.Value(KeySessionCreationHandler); v != nil {
		return v.(SessionCreationHandler)
	}
	return nil
}

func WithLoginFormHandler(req *saml.IdpAuthnRequest, cb ...func(next LoginFormHandler) LoginFormHandler) {
	var c = GetLoginFormHandler(req)
	for _, cb := range cb {
		c = cb(c)
	}
	req.Context = context.WithValue(req.Context, KeyLoginFormCallback, c)
}

func GetLoginFormHandler(req *saml.IdpAuthnRequest) LoginFormHandler {
	if v := req.Context.Value(KeyLoginFormCallback); v != nil {
		return v.(LoginFormHandler)
	}
	return nil
}

type SessionsStorer interface {
	Store(w http.ResponseWriter, req *saml.IdpAuthnRequest, session *saml.Session) error
	Get(w http.ResponseWriter, req *saml.IdpAuthnRequest) (session *saml.Session, err error)
	Delete(w http.ResponseWriter, req *saml.IdpAuthnRequest) (session *saml.Session, err error)
}

// GetSession returns the *Session for this request.
//
// If the remote user has specified a username and password in the request
// then it is validated against the user database. If valid it sets a
// cookie and returns the newly created session object.
//
// If the remote user has specified invalid credentials then a login form
// is returned with an English-language toast telling the user their
// password was invalid.
//
// If a session cookie already exists and represents a valid session,
// then the session is returned
//
// If neither credentials nor a valid session cookie exist, this function
// sends a login form and returns nil.
func (s *Server) GetSession(w http.ResponseWriter, req *saml.IdpAuthnRequest) (session *saml.Session) {
	lfHandler := GetLoginFormHandler(req)

	// if we received login credentials then maybe we can create a session
	if req.HTTPRequest.Method == "POST" {

		user, err := s.Users.Authenticates(req)
		if err != nil {
			lfHandler.Handle(w, req, err)
			return nil
		}

		session = saml.NewSession()
		session.User = user
		session.NameID = user.ID()
		session.UserName = user.Name()
		session.UserEmail = user.Email()

		scHandler := GetSessionCreationHandler(req)

		if session, err = scHandler.Handle(req, user, session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}

		if err := s.Sessions.Store(w, req, session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}
		return
	}

	var err error

	if session, err = s.Sessions.Get(w, req); err != nil {
		if err == ErrNotFound {
			lfHandler.Handle(w, req, nil)
			return nil
		}
	} else if session != nil {
		if !session.ExpireTime.IsZero() && saml.TimeNow().After(session.ExpireTime) {
			lfHandler.Handle(w, req, nil)
			return nil
		}
		return
	}

	lfHandler.Handle(w, req, err)
	return nil
}
