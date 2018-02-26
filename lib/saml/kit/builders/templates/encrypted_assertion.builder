# frozen_string_literal: true

xml.EncryptedAssertion xmlns: Saml::Kit::Namespaces::ASSERTION do
  encryption_for(xml: xml) do |xml|
    render assertion, xml: xml
  end
end
