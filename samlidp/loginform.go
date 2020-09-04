package samlidp

import (
	"encoding/base64"
	"net/http"
	"text/template"

	saml "github.com/moisespsena-go/xsaml"
)

type LoginFormDataInputOptions struct {
	UserInputType,
	UserLabel,
	UserPlaceholder,
	PasswordLabel,
	PasswordPlaceholder,
	SubmitLabel string
}

var DefaultLoginFormDataInputOptions = LoginFormDataInputOptions{
	PasswordLabel:       "Password",
	PasswordPlaceholder: "your password",
	UserPlaceholder:     "your user name",
	UserLabel:           "User",
	UserInputType:       "text",
	SubmitLabel:         "Log In",
}

func (this *LoginFormDataInputOptions) Merge(opt ...*LoginFormDataInputOptions) *LoginFormDataInputOptions {
	for _, opt := range opt {
		if opt == nil {
			continue
		}
		if opt.PasswordLabel != "" {
			this.PasswordLabel = opt.PasswordLabel
		}
		if opt.PasswordPlaceholder != "" {
			this.PasswordPlaceholder = opt.PasswordPlaceholder
		}
		if opt.SubmitLabel != "" {
			this.SubmitLabel = opt.SubmitLabel
		}
		if opt.UserInputType != "" {
			this.UserInputType = opt.UserInputType
		}
		if opt.UserLabel != "" {
			this.UserLabel = opt.UserLabel
		}
		if opt.UserPlaceholder != "" {
			this.UserPlaceholder = opt.UserPlaceholder
		}
	}
	return this
}

func (this LoginFormDataInputOptions) Copy(opt ...*LoginFormDataInputOptions) *LoginFormDataInputOptions {
	return this.Merge(opt...)
}

type LoginFormData struct {
	Req *saml.IdpAuthnRequest

	Toast,
	URL,
	SAMLRequest,
	RelayState string

	LoginFormDataInputOptions
}

func NewLoginFormData(req *saml.IdpAuthnRequest, err error, inputOptions ...*LoginFormDataInputOptions) *LoginFormData {
	var toast string

	if err != nil {
		toast = err.Error()
	}

	var iopt *LoginFormDataInputOptions
	req.Context, iopt = ContextGetOrSetLoginFormDataInputOptions(req.Context)
	iopt = iopt.Copy(&DefaultLoginFormDataInputOptions).Merge(inputOptions...)

	return &LoginFormData{
		req,
		toast,
		req.IDP.SsoURL(req.HTTPRequest),
		base64.StdEncoding.EncodeToString(req.RequestBuffer),
		req.RelayState,
		*iopt,
	}
}

var DefaultLoginFormHandler = LoginFormHandlerFunc(func(w http.ResponseWriter, req *saml.IdpAuthnRequest, err error) {
	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<html>` +
		`<p>{{.Toast}}</p>` +
		`<form method="post" action="{{.URL}}">` +
		`{{.UserLabel}}: <input type="{{.UserInputType}}" name="user" placeholder="{{.UserPlaceholder}}" value="" /><br />` +
		`{{.PasswordLabel}}: <input type="password" name="password" placeholder="{{.PasswordPlaceholder}}" value="" /><br />` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="{{.SubmitLabel}}" />` +
		`</form>` +
		`</html>`))

	data := NewLoginFormData(req, err)
	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
})
