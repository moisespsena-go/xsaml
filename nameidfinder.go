package saml

type NameIDFinder interface {
	Find(req *IdpAuthnRequest, session *Session) (nameID string, err error)
}

type NameIDFinderFunc func(req *IdpAuthnRequest, session *Session) (nameID string, err error)

func (this NameIDFinderFunc) Find(req *IdpAuthnRequest, session *Session) (string, error) {
	return this(req, session)
}

func NewNameIDFinder(f func(req *IdpAuthnRequest, session *Session) (nameID string, err error)) NameIDFinder {
	return NameIDFinderFunc(f)
}

type NameIDFinders []NameIDFinder

func (this NameIDFinders) Find(req *IdpAuthnRequest, session *Session) (nameID string, err error) {
	for _, finder := range this {
		if nameID, err = finder.Find(req, session); err != nil || nameID != "" {
			return
		}
	}
	return
}

func (this *NameIDFinders) Prepend(f ...NameIDFinder) {
	*this = append(append(NameIDFinders{}, f...), *this...)
}

func (this *NameIDFinders) Append(f ...NameIDFinder) {
	*this = append(*this, f...)
}

func NewNameIDProvider(finder NameIDFinder) AttributesProvider {
	return NewAttributesProvider(func(req *IdpAuthnRequest, session *Session) (err error) {
		var nameId string
		nameId, err = finder.Find(req, session)
		if nameId != "" && err == nil {
			session.NameID = nameId
		}
		return
	})
}
