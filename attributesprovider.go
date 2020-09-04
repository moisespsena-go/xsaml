package saml

// AttributesProvider is an interface used by IdentityProvider to provides the
// user session attributes.
type AttributesProvider interface {
	Provides(req *IdpAuthnRequest, session *Session) (err error)
}

type AttributesProviderFunc func(req *IdpAuthnRequest, session *Session) (err error)

func NewAttributesProvider(f func(req *IdpAuthnRequest, session *Session) (err error)) AttributesProvider {
	return AttributesProviderFunc(f)
}

func (this AttributesProviderFunc) Provides(req *IdpAuthnRequest, session *Session) error {
	return this(req, session)
}

type AttributesProviders []AttributesProvider

func (this *AttributesProviders) Add(ap ...AttributesProvider) {
	*this = append(*this, ap...)
}

func (this *AttributesProviders) Provides(req *IdpAuthnRequest, session *Session) (err error) {
	for _, ap := range *this {
		if err = ap.Provides(req, session); err != nil {
			return
		}
	}
	return
}