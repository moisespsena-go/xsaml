package gsuite

import (
	"errors"
	"strings"

	saml "github.com/moisespsena-go/xsaml"
	"github.com/moisespsena-go/xsaml/samlidp"
)

func RequestSetup(req *saml.IdpAuthnRequest, descriptor *saml.EntityDescriptor) (err error) {
	var opts *samlidp.LoginFormDataInputOptions
	req.Context, opts = samlidp.ContextGetOrSetLoginFormDataInputOptions(req.Context)
	opts.UserInputType = "email"
	opts.UserLabel = "!!Email!!"
	opts.UserPlaceholder = "!!Your mail address!!"
	if req.ServiceProvider == nil {
		req.ServiceProvider = saml.NewIDPServiceProvider(descriptor, &DefaultAssertionMaker{})
	}
	samlidp.WithSessionCreationHandler(req, func(next samlidp.SessionCreationHandler) samlidp.SessionCreationHandler {
		return samlidp.SessionCreationHandlerFunc(func(req *saml.IdpAuthnRequest, user samlidp.User, session *saml.Session) (*saml.Session, error) {
			if !strings.Contains(session.NameID, "@") {
				return nil, errors.New("bad gsuite NameID for session: the NameID is not a e-mail address")
			}
			session.UserEmail = session.NameID
			return next.Handle(req, user, session)
		})
	})
	return nil
}

type GSuiteMailAddressFinder interface {
	Find(req *saml.IdpAuthnRequest, session *saml.Session, domain string) (email string, err error)
}

type GSuiteMailAddressFinderFunc func(req *saml.IdpAuthnRequest, session *saml.Session, domain string) (email string, err error)

func (this GSuiteMailAddressFinderFunc) Find(req *saml.IdpAuthnRequest, session *saml.Session, domain string) (string, error) {
	return this(req, session, domain)
}

func NewGSuiteMailAddressFinder(f func(req *saml.IdpAuthnRequest, session *saml.Session, domain string) (email string, err error)) GSuiteMailAddressFinder {
	return GSuiteMailAddressFinderFunc(f)
}

// NewGSuiteMailAddressProvider this method is not valid for multiple domains in gsuinte account
func NewGSuiteMailAddressProvider(finder GSuiteMailAddressFinder) saml.AttributesProvider {
	return saml.NewNameIDProvider(saml.NewNameIDFinder(func(req *saml.IdpAuthnRequest, session *saml.Session) (nameID string, err error) {
		domain := GetDomain(req)
		if strings.HasSuffix(session.UserEmail, "@"+domain) {
			return session.UserEmail, nil
		}
		return finder.Find(req, session, domain)
	}))
}

func Metadata(domain string) []byte {
	return []byte(`<EntityDescriptor entityID="google.com/a/` + domain + `" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                  Location="https://www.google.com/a/` + domain + `/acs"/>
    </SPSSODescriptor>
</EntityDescriptor>`)
}

func MetadataIdentity(domain string) (metadata *saml.EntityDescriptor, err error) {
	return samlidp.ServiceProviderParseMetadata(Metadata(domain))
}

type ServicesProvider struct {
	AutoRegister bool
	metadata     *saml.EntityDescriptor
}

func (this *ServicesProvider) Get(req *saml.IdpAuthnRequest, ID string) (provider saml.IDPServiceProvider, err error) {
	var opts *samlidp.LoginFormDataInputOptions
	req.Context, opts = samlidp.ContextGetOrSetLoginFormDataInputOptions(req.Context)
	opts.UserInputType = "email"
	opts.UserLabel = "!!Email!!"
	opts.UserPlaceholder = "!!Your mail address!!"

	return saml.NewIDPServiceProvider(this.metadata, &DefaultAssertionMaker{}), nil
}

func GetDomain(req *saml.IdpAuthnRequest) string {
	parts := strings.Split(req.Request.AssertionConsumerServiceURL, "/")
	return parts[len(parts)-2]
}

func ParseDomainFromServiceProviderEntityID(url string) string {
	if ValidServiceURL(url) {
		parts := strings.Split(url, "/")
		return parts[len(parts)-1]
	}
	return ""
}

func ValidServiceURL(url string) bool {
	return strings.Contains(url, "google.com/a/")
}
