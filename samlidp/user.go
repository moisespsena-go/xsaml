package samlidp

import (
	"errors"
	"github.com/moisespsena-go/xsaml"
	"net/http"
)

var ErrInvalidUserOrPassword = errors.New("Invalid user or password")

type UsersServiceProvider interface {
	Authenticates(req *saml.IdpAuthnRequest) (user User, err error)
	Get(r *http.Request, key string) (user User, err error)
}

type User interface {
	ID() string
	Name() string
	Email() string
}
