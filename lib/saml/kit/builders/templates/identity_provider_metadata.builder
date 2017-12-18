xml.IDPSSODescriptor descriptor_options do
  configuration.certificates(use: :signing).each do |certificate|
    render certificate, xml: xml
  end
  configuration.certificates(use: :encryption).each do |certificate|
    render certificate, xml: xml
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
