package samlidp

import (
	"errors"
	"github.com/moisespsena-go/xsaml"
)

var ErrServiceProviderNotFound = errors.New("service provider not found")

type ServicesProvider interface {
	Get(req *saml.IdpAuthnRequest, ID string) (saml.IDPServiceProvider, error)
}

type ServicesProviders []ServicesProvider

func (providers ServicesProviders) Add(p ...ServicesProvider) ServicesProviders {
	return append(providers, p...)
}

func (providers ServicesProviders) Get(req *saml.IdpAuthnRequest, ID string) (sp saml.IDPServiceProvider, err error) {
	for _, p := range providers {
		if sp, err = p.Get(req, ID); err != ErrServiceProviderNotFound {
			return
		}
		err = nil
	}
	return nil, ErrServiceProviderNotFound
}

// Service represents a configured SP for whom this IDP provides authentication services.
type Service struct {
	// Name is the name of the service provider
	Name string

	// Metdata is the XML metadata of the service provider.
	Metadata saml.EntityDescriptor
}

// GetServiceProvider returns the Service Provider metadata for the
// service provider ID, which is typically the service provider's
// metadata URL. If an appropriate service provider cannot be found then
// the returned error must be os.ErrNotExist.
func (s *Server) GetServiceProvider(req *saml.IdpAuthnRequest, serviceProviderID string) (saml.IDPServiceProvider, error) {
	return s.Services.Get(req, serviceProviderID)
}
