package saml

import (
	"crypto/rand"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// TimeNow is a function that returns the current time. The default
// value is time.Now, but it can be replaced for testing.
var TimeNow = func() time.Time { return time.Now().UTC() }

// Clock is assigned to dsig validation and signing contexts if it is
// not nil, otherwise the default clock is used.
var Clock *dsig.Clock

// RandReader is the io.Reader that produces cryptographically random
// bytes when they are need by the library. The default value is
// rand.Reader, but it can be replaced for testing.
var RandReader = rand.Reader

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

func RandomBytes(n ...int) []byte {
	var N int
	if len(n) == 0 || n[0] == 0 {
		N = 32
	} else {
		N = n[0]
	}
	rv := make([]byte, N)
	if _, err := RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

func BoolPtr(b bool) *bool {
	return &b
}