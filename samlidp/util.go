package samlidp

import (
	"errors"
	"io/ioutil"

	"encoding/xml"

	"io"

	saml "github.com/moisespsena-go/xsaml"
)

func ServiceProviderParseMetadata(bytes []byte) (spMetadata *saml.EntityDescriptor, err error) {
	spMetadata = &saml.EntityDescriptor{}

	if err := xml.Unmarshal(bytes, &spMetadata); err != nil {
		if err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}

			if err := xml.Unmarshal(bytes, &entities); err != nil {
				return nil, err
			}

			for _, e := range entities.EntityDescriptors {
				if len(e.SPSSODescriptors) > 0 {
					return &e, nil
				}
			}

			// there were no SPSSODescriptors in the response
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return nil, err
	}

	return spMetadata, nil
}

func ServiceProviderParseMetadataR(r io.Reader) (spMetadata *saml.EntityDescriptor, err error) {
	var bytes []byte

	if bytes, err = ioutil.ReadAll(r); err != nil {
		return nil, err
	}

	return ServiceProviderParseMetadata(bytes)
}
