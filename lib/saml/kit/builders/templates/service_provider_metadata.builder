xml.instruct!
xml.EntityDescriptor entity_descriptor_options do
  signature.template(id)
  xml.SPSSODescriptor descriptor_options do
    if configuration.signing_certificate_pem.present?
      xml.KeyDescriptor use: "signing" do
        xml.KeyInfo "xmlns": Saml::Kit::Namespaces::XMLDSIG do
          xml.X509Data do
            xml.X509Certificate configuration.stripped_signing_certificate
          end
        end
      end
    end
    if configuration.encryption_certificate_pem.present?
      xml.KeyDescriptor use: "encryption" do
        xml.KeyInfo "xmlns": Saml::Kit::Namespaces::XMLDSIG do
          xml.X509Data do
            xml.X509Certificate configuration.stripped_encryption_certificate
          end
        end
      end
    end
    logout_urls.each do |item|
      xml.SingleLogoutService Binding: item[:binding], Location: item[:location]
    end
    name_id_formats.each do |format|
      xml.NameIDFormat format
    end
    acs_urls.each_with_index do |item, index|
      xml.AssertionConsumerService Binding: item[:binding], Location: item[:location], index: index, isDefault: index == 0 ? true : false
    end
  end
  xml.Organization do
    xml.OrganizationName organization_name, 'xml:lang': "en"
    xml.OrganizationDisplayName organization_name, 'xml:lang': "en"
    xml.OrganizationURL organization_url, 'xml:lang': "en"
  end
  xml.ContactPerson contactType: "technical" do
    xml.Company "mailto:#{contact_email}"
  end
end
