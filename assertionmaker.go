package saml

import (
	"fmt"
	"regexp"
	"strconv"
)

// AssertionMaker is an interface used by IdentityProvider to construct the
// assertion for a request. The default implementation is DefaultAssertionMaker,
// which is used if not AssertionMaker is specified.
type AssertionMaker interface {
	// MakeAssertion constructs an assertion from session and the request and
	// assigns it to req.Assertion.
	MakeAssertion(req *IdpAuthnRequest, session *Session) error
}

// DefaultAssertionMaker produces a SAML assertion for the
// given request and assigns it to req.Assertion.
type DefaultAssertionMaker struct {
}

// MakeAssertion implements AssertionMaker. It produces a SAML assertion from the
// given request and assigns it to req.Assertion.
func (DefaultAssertionMaker) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	var attributes = Attributes{}

	var attributeConsumingService *AttributeConsumingService
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
		attributeConsumingService = &AttributeConsumingService{}
	}

	for _, requestedAttribute := range attributeConsumingService.RequestedAttributes {
		if requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" || requestedAttribute.NameFormat == "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" {
			attrName := requestedAttribute.Name
			attrName = regexp.MustCompile("[^A-Za-z0-9]+").ReplaceAllString(attrName, "")
			switch attrName {
			case "email", "mail",
				"emailaddress":
				attributes.Set(&Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserEmail,
					}},
				})
			case "name", "fullname", "cn", "commonname":
				attributes.Set(&Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserCommonName,
					}},
				})
			case "givenname", "firstname":
				attributes.Set(&Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserGivenName,
					}},
				})
			case "surname", "lastname", "familyname":
				attributes.Set(&Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserSurname,
					}},
				})
			case "user", "username":
				attributes.Set(&Attribute{
					FriendlyName: requestedAttribute.FriendlyName,
					Name:         requestedAttribute.Name,
					NameFormat:   requestedAttribute.NameFormat,
					Values: []AttributeValue{{
						Type:  "xs:string",
						Value: session.UserName,
					}},
				})
			case "uid", "userid", "id":
				var value = AttributeValue{Type: "xs:integer"}
				switch typ := session.User.(type) {
				case interface{ GetID() string }:
					value.Value = "xs:string"
					value.Value = typ.GetID()
				case interface{ GetID() int }:
					value.Value = strconv.Itoa(typ.GetID())
				case interface{ GetID() int64 }:
					value.Value = fmt.Sprintf("%d", typ.GetID())
				case interface{ GetID() int32 }:
					value.Value = fmt.Sprintf("%d", typ.GetID())
				default:
					value.Value = "xs:string"
					value.Value = session.NameID
				}
				if value.Value != "" {
					attributes.Set(&Attribute{
						FriendlyName: requestedAttribute.FriendlyName,
						Name:         requestedAttribute.Name,
						NameFormat:   requestedAttribute.NameFormat,
						Values:       []AttributeValue{value},
					})
				}
			}

		}
	}

	if session.UserName != "" {
		attributes.Set(&Attribute{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes.Set(&Attribute{
			FriendlyName: "email",
			Name:         "urn:oid:1.3.6.1.4.1.1466.115.121.1.39",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
	}

	if session.UserSurname != "" {
		attributes.Set(&Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}

	if session.UserGivenName != "" {
		attributes.Set(&Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	if session.UserCommonName != "" {
		attributes.Set(&Attribute{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserCommonName,
			}},
		})
	}

	if len(session.Groups) != 0 {
		groupMemberAttributeValues := []AttributeValue{}
		for _, group := range session.Groups {
			groupMemberAttributeValues = append(groupMemberAttributeValues, AttributeValue{
				Type:  "xs:string",
				Value: group,
			})
		}
		attributes.Set(&Attribute{
			FriendlyName: "eduPersonAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       groupMemberAttributeValues,
		})
	}

	if session.Attributes != nil {
		for _, attr := range session.Attributes {
			attributes.Merge(attr)
		}
	}

	// allow for some clock skew in the validity period using the
	// issuer's apparent clock.
	notBefore := req.Now.Add(-1 * MaxClockSkew)
	var notOnOrAfterAfter = session.ExpireTime
	if notOnOrAfterAfter.IsZero() {
		notOnOrAfterAfter = req.Now.Add(MaxIssueDelay)
		if notBefore.Before(req.Request.IssueInstant) {
			notBefore = req.Request.IssueInstant
			notOnOrAfterAfter = notBefore.Add(MaxIssueDelay)
		}
	}

	req.Assertion = &Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata(req.HTTPRequest).EntityID,
		},
		Subject: &Subject{
			NameID: &NameID{
				Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
				NameQualifier:   req.IDP.Metadata(req.HTTPRequest).EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           session.NameID,
			},
			SubjectConfirmations: []SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      req.HTTPRequest.RemoteAddr,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: req.Now.Add(MaxIssueDelay),
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfterAfter,
			AudienceRestrictions: []AudienceRestriction{
				{
					Audience: Audience{Value: req.ServiceProviderMetadata.EntityID},
				},
			},
		},
		AuthnStatements: []AuthnStatement{
			{
				AuthnInstant: session.CreateTime,
				SessionIndex: session.Index,
				AuthnContext: AuthnContext{
					AuthnContextClassRef: &AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []AttributeStatement{
			{
				Attributes: attributes.Values(),
			},
		},
	}

	return nil
}
