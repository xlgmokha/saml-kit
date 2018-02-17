xml.SPSSODescriptor descriptor_options do
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
  acs_urls.each_with_index do |item, index|
    xml.AssertionConsumerService Binding: item[:binding], Location: item[:location], index: index, isDefault: index.zero?
  end
end
