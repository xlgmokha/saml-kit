# frozen_string_literal: true

xml.EncryptedAssertion xmlns: Saml::Kit::Namespaces::ASSERTION do
  encrypt_data_for(xml: xml) do |xml|
    render assertion, xml: xml
  end
end
