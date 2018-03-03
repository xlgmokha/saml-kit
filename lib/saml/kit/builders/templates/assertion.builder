# frozen_string_literal: true

xml.Assertion(assertion_options) do
  xml.Issuer issuer
  signature_for(reference_id: reference_id, xml: xml)
  xml.Subject do
    xml.NameID name_id, Format: name_id_format
    xml.SubjectConfirmation Method: Saml::Kit::Namespaces::BEARER do
      xml.SubjectConfirmationData '', subject_confirmation_data_options
    end
  end
  if request.present?
    xml.Conditions conditions_options do
      xml.AudienceRestriction do
        xml.Audience request.issuer
      end
    end
  end
  xml.AuthnStatement authn_statement_options do
    xml.AuthnContext do
      xml.AuthnContextClassRef Saml::Kit::Namespaces::PASSWORD
    end
  end
  if assertion_attributes.any?
    xml.AttributeStatement do
      assertion_attributes.each do |key, value|
        xml.Attribute Name: key, NameFormat: Saml::Kit::Namespaces::URI, FriendlyName: key do
          xml.AttributeValue value.to_s
        end
      end
    end
  end
end
