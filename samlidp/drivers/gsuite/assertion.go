package gsuite

import (
	"fmt"

	saml "github.com/moisespsena-go/xsaml"
)

// DefaultAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type DefaultAssertionMaker struct {
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (DefaultAssertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	var attributeConsumingService *saml.AttributeConsumingService
	for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
		if acs.IsDefault != nil && *acs.IsDefault {
			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		attributeConsumingService = &saml.AttributeConsumingService{}
	}

	// allow for some clock skew in the validity period using the
	// issuer's apparent clock.
	notBefore := req.Now.Add(-1 * saml.MaxClockSkew)
	notOnOrAfterAfter := req.Now.Add(saml.MaxIssueDelay)
	if notBefore.Before(req.Request.IssueInstant) {
		notBefore = req.Request.IssueInstant
		notOnOrAfterAfter = notBefore.Add(saml.MaxIssueDelay)
	}

	req.Assertion = &saml.Assertion{
		ID:           fmt.Sprintf("id-%x", saml.RandomBytes(20)),
		IssueInstant: saml.TimeNow(),
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata(req.HTTPRequest).EntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:email",
				//NameQualifier:   req.IDP.Metadata(req.HTTPRequest).EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           session.NameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						Address:      req.HTTPRequest.RemoteAddr,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: req.Now.Add(saml.MaxIssueDelay),
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfterAfter,
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: session.CreateTime,
				SessionIndex: session.Index,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
					},
				},
			},
		},
	}

	return nil
}
