package main

import (
	"fmt"
	"net/http"
	"net/url"

	"crypto/tls"
	"crypto/x509"

	"crypto/rsa"

	"github.com/moisespsena-go/xsaml/samlsp"
)

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<p>Hello to SAML SP test page.</p>
<p><a href="/hello">Authenticaded Page</a></p>
`))
}

func hello(w http.ResponseWriter, r *http.Request) {
	attrs := samlsp.Token(r.Context()).Attributes
	fmt.Fprintf(w, `<p>Hello, %s!</p><p><a href="/onlySpLogout">[only SP logout]</a> <a href="/spAndIdpLogout">[SP and IDP logout]</a></p>`, attrs)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("/home/moi/.goenv/ecletus/src/github.com/moisespsena/go-identityd/data/config/server/localhost.cert", "/home/moi/.goenv/ecletus/src/github.com/moisespsena/go-identityd/data/config/server/localhost.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("http://localhost:5000/microvet/idp/5de971427c1dc963a9b22abf/metadata.xml")
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		IDPMetadataURL: idpMetadataURL,
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
	})
	app := http.HandlerFunc(hello)
	http.HandleFunc("/", index)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/hello/", samlSP.RequireAccount(app))
	http.Handle("/onlySpLogout", samlSP.Logouter())
	http.Handle("/spAndIdpLogout", samlSP.Logouter(&samlsp.LogouterOptions{CallbackUrl: "http://localhost:5000/microvet/auth/logout"}))
	http.Handle("/saml/", samlSP)
	http.ListenAndServe(":8000", nil)
}
