xml.Response response_options do
  xml.Issuer(issuer, xmlns: Saml::Kit::Namespaces::ASSERTION)
  signature_for(reference_id: id, xml: xml)
  xml.Status do
    xml.StatusCode Value: status_code
  end
  encryption_for(xml: xml) do |xml|
    xml.Assertion(assertion_options) do
      xml.Issuer issuer
      signature_for(reference_id: reference_id, xml: xml) unless encrypt
      xml.Subject do
        xml.NameID user.name_id_for(request.name_id_format), Format: request.name_id_format
        xml.SubjectConfirmation Method: Saml::Kit::Namespaces::BEARER do
          xml.SubjectConfirmationData "", subject_confirmation_data_options
        end
      end
      xml.Conditions conditions_options do
        xml.AudienceRestriction do
          xml.Audience request.issuer
        end
      end
      xml.AuthnStatement authn_statement_options do
        xml.AuthnContext do
          xml.AuthnContextClassRef Saml::Kit::Namespaces::PASSWORD
        end
      end
      assertion_attributes = user.assertion_attributes_for(request)
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
  end
end
