package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"text/template"
	"time"

	"github.com/pkg/errors"

	"github.com/beevik/etree"
	"github.com/moisespsena-go/xsaml/logger"
	"github.com/moisespsena-go/xsaml/xmlenc"
	dsig "github.com/russellhaering/goxmldsig"
)

type Attributes map[string]*Attribute

func (this *Attributes) Set(attr ...*Attribute) {
	if *this == nil {
		*this = make(Attributes)
	}
	for _, attr := range attr {
		(*this)[attr.Name] = attr
	}
}

func (this *Attributes) Merge(attr ...*Attribute) {
	if *this == nil {
		*this = make(Attributes)
	}
	for _, attr := range attr {
		if cur, ok := (*this)[attr.Name]; ok {
			cur.Update(attr)
		} else {
			(*this)[attr.Name] = attr
		}
	}
}

func (this Attributes) Get(name string) *Attribute {
	if this == nil {
		return nil
	}
	return this[name]
}

func (this *Attributes) Del(name string) *Attribute {
	if *this != nil {
		if attr, ok := (*this)[name]; ok {
			delete(*this, name)
			return attr
		}
	}
	return nil
}

func (this Attributes) Has(name string) (ok bool) {
	if this != nil {
		_, ok = this[name]
	}
	return
}

func (this Attributes) Values() []Attribute {
	result := make([]Attribute, len(this))
	if this != nil {
		i := 0
		for _, attr := range this {
			result[i] = *attr
			i++
		}
		sort.Slice(result, func(i, j int) bool {
			return result[i].Name < result[i].Name
		})
	}
	return result
}

// Session represents a user session. It is returned by the
// SessionProvider implementation's GetSession method. Fields here
// are used to set fields in the SAML assertion.
type Session struct {
	ID         string
	CreateTime time.Time
	ExpireTime time.Time
	Index      string

	NameID         string
	Groups         []string
	UserName       string
	UserEmail      string
	UserCommonName string
	UserSurname    string
	UserGivenName  string
	User           interface{}
	Attributes     Attributes
}

func NewSession() *Session {
	return &Session{
		ID:         base64.StdEncoding.EncodeToString(RandomBytes()),
		CreateTime: TimeNow(),
		ExpireTime: TimeNow().Add(time.Hour),
	}
}

// SessionProvider is an interface used by IdentityProvider to determine the
// Session associated with a request. For an example implementation, see
// GetSession in the samlidp package.
type SessionProvider interface {
	// GetSession returns the remote user session associated with the http.Request.
	//
	// If (and only if) the request is not associated with a session then GetSession
	// must complete the HTTP request and return nil.
	GetSession(w http.ResponseWriter, req *IdpAuthnRequest) *Session
}

type IDPServiceProvider interface {
	Metadata() *EntityDescriptor
	AssertionMaker() AssertionMaker
}

type IDPServiceProviderImpl struct {
	metadata       *EntityDescriptor
	assertionMaker AssertionMaker
}

func (this IDPServiceProviderImpl) Metadata() *EntityDescriptor {
	return this.metadata
}

func (this IDPServiceProviderImpl) AssertionMaker() AssertionMaker {
	return this.assertionMaker
}

func NewIDPServiceProvider(descriptor *EntityDescriptor, assertionMaker AssertionMaker) IDPServiceProvider {
	return &IDPServiceProviderImpl{descriptor, assertionMaker}
}

// ServiceProviderProvider is an interface used by IdentityProvider to look up
// service provider metadata for a request.
type ServiceProviderProvider interface {
	// GetServiceProvider returns the Service Provider with metadata and optional
	// assertion maker for the service provider ID, which is typically the service
	// provider's metadata URL. If an appropriate service provider cannot be found
	// then the returned error must be os.ErrNotExist.
	GetServiceProvider(req *IdpAuthnRequest, serviceProviderID string) (sp IDPServiceProvider, err error)
}

// IdentityProviderPaths the paths for IdentityProvider
type IdentityProviderPaths struct {
	// Metadata path for metadata.xml generator handler
	Metadata,
	// Metadata path for SSO handler
	SSO string
}

var DefaultIdentityProviderPaths = IdentityProviderPaths{
	Metadata: "metadata.xml",
	SSO:      "sso",
}

// IdentityProvider implements the SAML Identity Provider role (IDP).
//
// An identity provider receives SAML assertion requests and responds
// with SAML Assertions.
//
// You must provide a keypair that is used to
// sign assertions.
//
// You must provide an implementation of ServiceProviderProvider which
// returns
//
// You must provide an implementation of the SessionProvider which
// handles the actual authentication (i.e. prompting for a username
// and password).
type IdentityProvider struct {
	Key                     crypto.PrivateKey
	Logger                  logger.Interface
	Certificate             *x509.Certificate
	Intermediates           []*x509.Certificate
	Paths                   *IdentityProviderPaths
	URLFunc                 func(idp *IdentityProvider, r *http.Request, path ...string) string
	LogoutURL               func(idp *IdentityProvider, r *http.Request) string
	SetupRequestFunc        func(idp *IdentityProvider, r *IdpAuthnRequest) (err error)
	ServiceProviderProvider ServiceProviderProvider
	SessionProvider         SessionProvider
	AssertionMaker          AssertionMaker
	SignatureMethod         string
	IdpAuthnResponseFactory IdpAuthnResponseFactory
	AttributesProviders     AttributesProviders
}

func NewIdentityProvider(idp ...*IdentityProvider) *IdentityProvider {
	var IDP *IdentityProvider
	for _, IDP = range idp {
	}
	if IDP == nil {
		IDP = &IdentityProvider{}
	}
	if IDP.Paths == nil {
		IDP.Paths = &DefaultIdentityProviderPaths
	}
	if IDP.IdpAuthnResponseFactory == nil {
		IDP.IdpAuthnResponseFactory = DefaultIdpAuthnResponseFactory{}
	}
	return IDP
}

func (this *IdentityProvider) URL(r *http.Request, pth ...string) string {
	return this.URLFunc(this, r, pth...)
}

// Metadata returns the metadata structure for this identity provider.
func (this *IdentityProvider) Metadata(r *http.Request) *EntityDescriptor {
	var (
		certStr     = base64.StdEncoding.EncodeToString(this.Certificate.Raw)
		baseUrl     = this.URL(r)
		ssoUrl      = baseUrl+"/"+this.Paths.SSO
		metadataUrl = baseUrl+"/"+this.Paths.Metadata
	)

	ed := &EntityDescriptor{
		EntityID:      metadataUrl,
		ValidUntil:    TimeNow().Add(DefaultValidDuration),
		CacheDuration: DefaultValidDuration,
		IDPSSODescriptors: []IDPSSODescriptor{{
			SSODescriptor: SSODescriptor{
				RoleDescriptor: RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					KeyDescriptors: []KeyDescriptor{
						{
							Use: "signing",
							KeyInfo: KeyInfo{
								Certificate: certStr,
							},
						},
						{
							Use: "encryption",
							KeyInfo: KeyInfo{
								Certificate: certStr,
							},
							EncryptionMethods: []EncryptionMethod{
								{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
								{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
								{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
								{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
							},
						},
					},
				},
				NameIDFormats: []NameIDFormat{NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")},
			},
			SingleSignOnServices: []Endpoint{
				{
					Binding:  HTTPRedirectBinding,
					Location: ssoUrl,
				},
				{
					Binding:  HTTPPostBinding,
					Location: ssoUrl,
				},
			},
		}},
	}

	if this.LogoutURL != nil {
		logoutUrl := this.LogoutURL(this, r)
		ed.IDPSSODescriptors[0].SSODescriptor.SingleLogoutServices = []Endpoint{
			{
				Binding:  HTTPRedirectBinding,
				Location: logoutUrl,
			},
		}
	}

	return ed
}

func (this *IdentityProvider) RequestSetup(r *IdpAuthnRequest) (err error) {
	if this.SetupRequestFunc != nil {
		return this.SetupRequestFunc(this, r)
	}
	return
}

// Handler returns an http.Handler that serves the metadata and SSO
// URLs
func (this *IdentityProvider) Handler() http.Handler {
	panic("not implemented")
	mux := http.NewServeMux()
	//mux.HandleFunc(idp.MetadataURL.Path, idp.ServeMetadata)
	//mux.HandleFunc(idp.SSOURL.Path, idp.ServeSSO)
	return mux
}

// ServeMetadata is an http.HandlerFunc that serves the IDP metadata
func (this *IdentityProvider) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", "attachment; filename=metadata.xml")
	w.Write(this.Metadata(r).Bytes(true))
}

// ServeSSO handles SAML auth requests.
//
// When it gets a request for a user that does not have a valid session,
// then it prompts the user via XXX.
//
// If the session already exists, then it produces a SAML assertion and
// returns an HTTP response according to the specified binding. The
// only supported binding right now is the HTTP-POST binding which returns
// an HTML form in the appropriate format with Javascript to automatically
// submit that form the to service provider's Assertion Customer Service
// endpoint.
//
// If the SAML request is invalid or cannot be verified a simple StatusBadRequest
// response is sent.
//
// If the assertion cannot be created or returned, a StatusInternalServerError
// response is sent.
func (this *IdentityProvider) ServeSSO(w http.ResponseWriter, r *http.Request) {
	req, err := NewIdpAuthnRequest(this, r)
	if err != nil {
		this.Logger.Printf("failed to parse request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		this.Logger.Printf("failed to validate request: %s", err)
		if relayStateURL, err := url.Parse(req.RelayState); err == nil {
			if continueTo := relayStateURL.Query().Get("continue"); continueTo != "" {
				http.Redirect(w, r, continueTo, http.StatusTemporaryRedirect)
				return
			}
		}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// TODO(ross): we must check that the request ID has not been previously
	//   issued.

	session := this.SessionProvider.GetSession(w, req)
	if session == nil {
		return
	}

	if err = this.AttributesProviders.Provides(req, session); err != nil {
		this.Logger.Printf("failed to provides session attributes: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = this.IdpAuthnResponseFactory.Factory(req, session, w); err != nil {
		this.Logger.Printf("failed to create response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := req.WriteResponse(w); err != nil {
		this.Logger.Printf("failed to write response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (this *IdentityProvider) MetadataURL(r *http.Request) string {
	return this.URL(r, this.Paths.Metadata)
}

func (this *IdentityProvider) SsoURL(r *http.Request) string {
	return this.URL(r, this.Paths.SSO)
}

// ServeIDPInitiated handes an IDP-initiated authorization request. Requests of this
// type require us to know a registered service provider and (optionally) the RelayState
// that will be passed to the application.
func (this *IdentityProvider) ServeIDPInitiated(w http.ResponseWriter, r *http.Request, serviceProviderID string, relayState string) {
	req := &IdpAuthnRequest{
		IDP:         this,
		HTTPRequest: r,
		RelayState:  relayState,
		Now:         TimeNow(),
	}

	session := this.SessionProvider.GetSession(w, req)
	if session == nil {
		// If GetSession returns nil, it must have written an HTTP response, per the interface
		// (this is probably because it drew a login form or something)
		return
	}

	var err error
	sp, err := this.ServiceProviderProvider.GetServiceProvider(req, serviceProviderID)
	if err == os.ErrNotExist {
		this.Logger.Printf("cannot find service provider: %s", serviceProviderID)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	} else if err != nil {
		this.Logger.Printf("cannot find service provider %s: %v", serviceProviderID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	req.ServiceProviderMetadata = sp.Metadata()

	// find an ACS endpoint that we can use
	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.AssertionConsumerServices {
			if endpoint.Binding == HTTPPostBinding {
				req.ACSEndpoint = &endpoint
				req.SPSSODescriptor = &spssoDescriptor
				break
			}
		}
		if req.ACSEndpoint != nil {
			break
		}
	}
	if req.ACSEndpoint == nil {
		this.Logger.Printf("saml metadata does not contain an Assertion Customer Service url")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err = this.AttributesProviders.Provides(req, session); err != nil {
		this.Logger.Printf("provides session attributes failed: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if len(req.Response) == 0 {
		assertionMaker := sp.AssertionMaker()
		if assertionMaker == nil {
			assertionMaker = this.AssertionMaker
		}
		if assertionMaker == nil {
			assertionMaker = DefaultAssertionMaker{}
		}
		if err := assertionMaker.MakeAssertion(req, session); err != nil {
			this.Logger.Printf("failed to make assertion: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	if err = this.IdpAuthnResponseFactory.Factory(req, session, w); err != nil {
		this.Logger.Printf("failed to create response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := req.WriteResponse(w); err != nil {
		this.Logger.Printf("failed to write response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

type IdpAuthnResponseFactory interface {
	Factory(req *IdpAuthnRequest, session *Session, w http.ResponseWriter) (err error)
}

type DefaultIdpAuthnResponseFactory struct{}

func (DefaultIdpAuthnResponseFactory) Factory(req *IdpAuthnRequest, session *Session, w http.ResponseWriter) (err error) {
	idp := req.IDP
	if len(req.Response) == 0 {
		var assertionMaker = req.ServiceProvider.AssertionMaker()
		if assertionMaker == nil {
			assertionMaker = idp.AssertionMaker
			if assertionMaker == nil {
				assertionMaker = DefaultAssertionMaker{}
			}
		}
		if err := assertionMaker.MakeAssertion(req, session); err != nil {
			return fmt.Errorf("failed to make assertion: %s", err)
		}
	}
	if req.ResponseEl == nil {
		if err = req.MakeResponse(); err != nil {
			return
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	var b []byte
	if b, err = doc.WriteToBytes(); err != nil {
		return
	}
	req.Response = append([]byte(`<?xml version="1.0" encoding="UTF-8"?>\n`), b...)
	return
}

// IdpAuthnRequest is used by IdentityProvider to handle a single authentication request.
type IdpAuthnRequest struct {
	Context                 context.Context
	IDP                     *IdentityProvider
	HTTPRequest             *http.Request
	RelayState              string
	RequestBuffer           []byte
	Request                 AuthnRequest
	AttributesProviders     AttributesProviders
	ServiceProvider         IDPServiceProvider
	ServiceProviderMetadata *EntityDescriptor
	SPSSODescriptor         *SPSSODescriptor
	ACSEndpoint             *IndexedEndpoint
	Assertion               *Assertion
	AssertionEl             *etree.Element
	Response                []byte
	ResponseEl              *etree.Element
	Now                     time.Time

	baseURL, metadataURL, ssoURL string

	Data map[interface{}]interface{}
}

// NewIdpAuthnRequest returns a new IdpAuthnRequest for the given HTTP request to the authorization
// service.
func NewIdpAuthnRequest(idp *IdentityProvider, r *http.Request) (*IdpAuthnRequest, error) {
	req := &IdpAuthnRequest{
		Context:     context.Background(),
		IDP:         idp,
		HTTPRequest: r,
		Now:         TimeNow(),
		baseURL:     idp.URL(r),
		Data:        map[interface{}]interface{}{},
	}
	req.metadataURL = path.Join(req.baseURL, idp.Paths.Metadata)
	req.ssoURL = path.Join(req.baseURL, idp.Paths.SSO)

	switch r.Method {
	case "GET":
		compressedRequest, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
		if err != nil {
			return nil, fmt.Errorf("cannot decode request: %s", err)
		}
		req.RequestBuffer, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
		if err != nil {
			return nil, fmt.Errorf("cannot decompress request: %s", err)
		}
		req.RelayState = r.URL.Query().Get("RelayState")
	case "POST":
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		var err error
		req.RequestBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
		if err != nil {
			return nil, err
		}
		req.RelayState = r.PostForm.Get("RelayState")
	default:
		return nil, fmt.Errorf("method not allowed")
	}
	return req, nil
}

// Validate checks that the authentication request is valid and assigns
// the AuthnRequest and Metadata properties. Returns a non-nil error if the
// request is not valid.
func (this *IdpAuthnRequest) Validate() (err error) {
	if err = xml.Unmarshal(this.RequestBuffer, &this.Request); err != nil {
		return err
	}

	metadata := this.IDP.Metadata(this.HTTPRequest)
	// We always have exactly one IDP SSO descriptor
	if len(metadata.IDPSSODescriptors) != 1 {
		panic("expected exactly one IDP SSO descriptor in IDP metadata")
	}
	idpSsoDescriptor := metadata.IDPSSODescriptors[0]

	// TODO(ross): support signed authn requests
	// For now we do the safe thing and fail in the case where we think
	// requests might be signed.
	if idpSsoDescriptor.WantAuthnRequestsSigned != nil && *idpSsoDescriptor.WantAuthnRequestsSigned {
		return fmt.Errorf("Authn request signature checking is not currently supported")
	}

	// In http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf §3.4.5.2
	// we get a description of the Destination attribute:
	//
	//   If the message is signed, the Destination XML attribute in the root SAML
	//   element of the protocol message MUST contain the URL to which the sender
	//   has instructed the user agent to deliver the message. The recipient MUST
	//   then verify that the value matches the location at which the message has
	//   been received.
	//
	// We require the destination be correct either (a) if signing is enabled or
	// (b) if it was provided.
	mustHaveDestination := idpSsoDescriptor.WantAuthnRequestsSigned != nil && *idpSsoDescriptor.WantAuthnRequestsSigned
	mustHaveDestination = mustHaveDestination || this.Request.Destination != ""
	if mustHaveDestination {
		if this.Request.Destination != this.ssoURL {
			return fmt.Errorf("expected destination to be %q, not %q", this.ssoURL, this.Request.Destination)
		}
	}

	if this.Request.IssueInstant.Add(MaxIssueDelay).Before(this.Now) {
		return fmt.Errorf("request expired at %s",
			this.Request.IssueInstant.Add(MaxIssueDelay))
	}
	if this.Request.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2.0 got %v", this.Request.Version)
	}

	if err = this.IDP.RequestSetup(this); err != nil {
		return errors.Wrap(err, "setup request")
	}

	if this.ServiceProvider == nil {
		// find the service provider
		serviceProviderID := this.Request.Issuer.Value
		this.ServiceProvider, err = this.IDP.ServiceProviderProvider.GetServiceProvider(this, serviceProviderID)
		if err == os.ErrNotExist {
			return fmt.Errorf("cannot handle request from unknown service provider %s", serviceProviderID)
		} else if err != nil {
			return fmt.Errorf("cannot find service provider %s: %v", serviceProviderID, err)
		}
	}
	if this.ServiceProviderMetadata == nil {
		this.ServiceProviderMetadata = this.ServiceProvider.Metadata()
	}

	// Check that the ACS URL matches an ACS endpoint in the SP metadata.
	if err := this.getACSEndpoint(); err != nil {
		return fmt.Errorf("cannot find assertion consumer service: %v", err)
	}

	return nil
}

func (this *IdpAuthnRequest) ContextSet(key, value interface{}) *IdpAuthnRequest {
	this.Context = context.WithValue(this.Context, key, value)
	return this
}

func (this *IdpAuthnRequest) getACSEndpoint() error {
	if this.Request.AssertionConsumerServiceIndex != "" {
		for _, spssoDescriptor := range this.ServiceProviderMetadata.SPSSODescriptors {
			for _, spAssertionConsumerService := range spssoDescriptor.AssertionConsumerServices {
				if strconv.Itoa(spAssertionConsumerService.Index) == this.Request.AssertionConsumerServiceIndex {
					this.SPSSODescriptor = &spssoDescriptor
					this.ACSEndpoint = &spAssertionConsumerService
					return nil
				}
			}
		}
	}

	if this.Request.AssertionConsumerServiceURL != "" {
		for _, spssoDescriptor := range this.ServiceProviderMetadata.SPSSODescriptors {
			for _, spAssertionConsumerService := range spssoDescriptor.AssertionConsumerServices {
				if spAssertionConsumerService.Location == this.Request.AssertionConsumerServiceURL {
					this.SPSSODescriptor = &spssoDescriptor
					this.ACSEndpoint = &spAssertionConsumerService
					return nil
				}
			}
		}
	}

	// Some service providers, like the Microsoft Azure AD service provider, issue
	// assertion requests that don't specify an ACS url at all.
	if this.Request.AssertionConsumerServiceURL == "" && this.Request.AssertionConsumerServiceIndex == "" {
		// find a default ACS binding in the metadata that we can use
		for _, spssoDescriptor := range this.ServiceProviderMetadata.SPSSODescriptors {
			for _, spAssertionConsumerService := range spssoDescriptor.AssertionConsumerServices {
				if spAssertionConsumerService.IsDefault != nil && *spAssertionConsumerService.IsDefault {
					switch spAssertionConsumerService.Binding {
					case HTTPPostBinding, HTTPRedirectBinding:
						this.SPSSODescriptor = &spssoDescriptor
						this.ACSEndpoint = &spAssertionConsumerService
						return nil
					}
				}
			}
		}

		// if we can't find a default, use *any* ACS binding
		for _, spssoDescriptor := range this.ServiceProviderMetadata.SPSSODescriptors {
			for _, spAssertionConsumerService := range spssoDescriptor.AssertionConsumerServices {
				switch spAssertionConsumerService.Binding {
				case HTTPPostBinding, HTTPRedirectBinding:
					this.SPSSODescriptor = &spssoDescriptor
					this.ACSEndpoint = &spAssertionConsumerService
					return nil
				}
			}
		}
	}

	return os.ErrNotExist // no ACS url found or specified
}

// The Canonicalizer prefix list MUST be empty. Various implementations
// (maybe ours?) do not appear to support non-empty prefix lists in XML C14N.
const canonicalizerPrefixList = ""

// MakeAssertionEl sets `AssertionEl` to a signed, possibly encrypted, version of `Assertion`.
func (this *IdpAuthnRequest) MakeAssertionEl() error {
	keyPair := tls.Certificate{
		Certificate: [][]byte{this.IDP.Certificate.Raw},
		PrivateKey:  this.IDP.Key,
		Leaf:        this.IDP.Certificate,
	}
	for _, cert := range this.IDP.Intermediates {
		keyPair.Certificate = append(keyPair.Certificate, cert.Raw)
	}
	keyStore := dsig.TLSCertKeyStore(keyPair)

	signatureMethod := this.IDP.SignatureMethod
	if signatureMethod == "" {
		signatureMethod = dsig.RSASHA1SignatureMethod
	}

	signingContext := dsig.NewDefaultSigningContext(keyStore)
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(canonicalizerPrefixList)
	if err := signingContext.SetSignatureMethod(signatureMethod); err != nil {
		return err
	}

	assertionEl := this.Assertion.Element()

	signedAssertionEl, err := signingContext.SignEnveloped(assertionEl)
	if err != nil {
		return err
	}

	sigEl := signedAssertionEl.Child[len(signedAssertionEl.Child)-1]
	this.Assertion.Signature = sigEl.(*etree.Element)
	signedAssertionEl = this.Assertion.Element()

	certBuf, err := this.getSPEncryptionCert()
	if err == os.ErrNotExist {
		this.AssertionEl = signedAssertionEl
		return nil
	} else if err != nil {
		return err
	}

	var signedAssertionBuf []byte
	{
		doc := etree.NewDocument()
		doc.SetRoot(signedAssertionEl)
		signedAssertionBuf, err = doc.WriteToBytes()
		if err != nil {
			return err
		}
	}

	encryptor := xmlenc.OAEP()
	encryptor.BlockCipher = xmlenc.AES128CBC
	encryptor.DigestMethod = &xmlenc.SHA1
	encryptedDataEl, err := encryptor.Encrypt(certBuf, signedAssertionBuf)
	if err != nil {
		return err
	}
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

	encryptedAssertionEl := etree.NewElement("saml:EncryptedAssertion")
	encryptedAssertionEl.AddChild(encryptedDataEl)
	this.AssertionEl = encryptedAssertionEl

	return nil
}

// WriteResponse writes the `Response` to the http.ResponseWriter. If
// `Response` is not already set, it calls MakeResponse to produce it.
func (this *IdpAuthnRequest) WriteResponse(w http.ResponseWriter) (err error) {
	if len(this.Response) == 0 {
		return errors.New("empty response")
	}

	// the only supported binding is the HTTP-POST binding
	switch this.ACSEndpoint.Binding {
	case HTTPPostBinding:
		tmpl := template.Must(template.New("saml-post-form").Parse(`<html>` +
			`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
			`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
			`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
			`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
			`</form>` +
			`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
			`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
			`</html>`))
		data := struct {
			URL          string
			SAMLResponse string
			RelayState   string
		}{
			URL:          this.ACSEndpoint.Location,
			SAMLResponse: base64.StdEncoding.EncodeToString(this.Response),
			RelayState:   this.RelayState,
		}

		buf := bytes.NewBuffer(nil)
		if err := tmpl.Execute(buf, data); err != nil {
			return err
		}
		if _, err := io.Copy(w, buf); err != nil {
			return err
		}
		return nil

	default:
		return fmt.Errorf("%s: unsupported binding %s",
			this.ServiceProviderMetadata.EntityID,
			this.ACSEndpoint.Binding)
	}
}

// getSPEncryptionCert returns the certificate which we can use to encrypt things
// to the SP in PEM format, or nil if no such certificate is found.
func (this *IdpAuthnRequest) getSPEncryptionCert() (*x509.Certificate, error) {
	certStr := ""
	for _, keyDescriptor := range this.SPSSODescriptor.KeyDescriptors {
		if keyDescriptor.Use == "encryption" {
			certStr = keyDescriptor.KeyInfo.Certificate
			break
		}
	}

	// If there are no certs explicitly labeled for encryption, return the first
	// non-empty cert we find.
	if certStr == "" {
		for _, keyDescriptor := range this.SPSSODescriptor.KeyDescriptors {
			if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
				certStr = keyDescriptor.KeyInfo.Certificate
				break
			}
		}
	}

	if certStr == "" {
		return nil, os.ErrNotExist
	}

	// cleanup whitespace and re-encode a PEM
	certStr = regexp.MustCompile(`\s+`).ReplaceAllString(certStr, "")
	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("cannot decode certificate base64: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate: %v", err)
	}
	return cert, nil
}

// unmarshalEtreeHack parses `el` and sets values in the structure `v`.
//
// This is a hack -- it first serializes the element, then uses xml.Unmarshal.
func unmarshalEtreeHack(el *etree.Element, v interface{}) error {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(buf, v)
}

// MakeResponse creates and assigns a new SAML response in ResponseEl. `Assertion` must
// be non-nil. If MakeAssertionEl() has not been called, this function calls it for
// you.
func (this *IdpAuthnRequest) MakeResponse() error {
	if this.AssertionEl == nil {
		if err := this.MakeAssertionEl(); err != nil {
			return err
		}
	}

	response := &Response{
		Destination:  this.ACSEndpoint.Location,
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: this.Request.ID,
		IssueInstant: this.Now,
		Version:      "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  this.metadataURL,
		},
		Status: Status{
			StatusCode: StatusCode{
				Value: StatusSuccess,
			},
		},
	}

	responseEl := response.Element()
	responseEl.AddChild(this.AssertionEl) // AssertionEl either an EncryptedAssertion or Assertion element

	// Sign the response element (we've already signed the Assertion element)
	{
		keyPair := tls.Certificate{
			Certificate: [][]byte{this.IDP.Certificate.Raw},
			PrivateKey:  this.IDP.Key,
			Leaf:        this.IDP.Certificate,
		}
		for _, cert := range this.IDP.Intermediates {
			keyPair.Certificate = append(keyPair.Certificate, cert.Raw)
		}
		keyStore := dsig.TLSCertKeyStore(keyPair)

		signatureMethod := this.IDP.SignatureMethod
		if signatureMethod == "" {
			signatureMethod = dsig.RSASHA1SignatureMethod
		}

		signingContext := dsig.NewDefaultSigningContext(keyStore)
		signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(canonicalizerPrefixList)
		if err := signingContext.SetSignatureMethod(signatureMethod); err != nil {
			return err
		}

		signedResponseEl, err := signingContext.SignEnveloped(responseEl)
		if err != nil {
			return err
		}

		sigEl := signedResponseEl.ChildElements()[len(signedResponseEl.ChildElements())-1]
		response.Signature = sigEl
		responseEl = response.Element()
		responseEl.AddChild(this.AssertionEl)
	}

	this.ResponseEl = responseEl
	return nil
}
