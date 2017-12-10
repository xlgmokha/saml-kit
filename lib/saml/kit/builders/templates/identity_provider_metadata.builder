xml.instruct!
xml.EntityDescriptor entity_descriptor_options do
  signature.template(id)
  xml.IDPSSODescriptor idp_sso_descriptor_options do
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
    single_sign_on_urls.each do |item|
      xml.SingleSignOnService Binding: item[:binding], Location: item[:location]
    end
    attributes.each do |attribute|
      xml.tag! 'saml:Attribute', Name: attribute
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
