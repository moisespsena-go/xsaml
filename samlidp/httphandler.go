package samlidp

import (
	"encoding/json"
	"net/http"

	saml "github.com/moisespsena-go/xsaml"
)

// HTTPLoginHandle handles the `POST /login` and `GET /login` forms. If credentials are present
// in the request body, then they are validated. For valid credentials, the response is a
// 200 OK and the JSON session object. For invalid credentials, the HTML login prompt form
// is sent.
func (s *Server) HTTPLoginHandle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	session := s.GetSession(w, &saml.IdpAuthnRequest{IDP: s.IDP, HTTPRequest: r})
	if session == nil {
		return
	}
	json.NewEncoder(w).Encode(session)
}

func (s *Server) HTTPMetadataHandle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	s.idpConfigMu.RLock()
	defer s.idpConfigMu.RUnlock()
	s.IDP.ServeMetadata(w, r)
}

func (s *Server) HTTPSSOHandle(w http.ResponseWriter, r *http.Request) {
	s.idpConfigMu.RLock()
	defer s.idpConfigMu.RUnlock()
	s.IDP.ServeSSO(w, r)
}
