RSpec::Matchers.define :have_xpath do |xpath|
  match do |actual|
    namespaces = {
      "NameFormat": Saml::Kit::Namespaces::ATTR_SPLAT,
      "ds": ::Xml::Kit::Namespaces::XMLDSIG,
      "md": Saml::Kit::Namespaces::METADATA,
      "saml": Saml::Kit::Namespaces::ASSERTION,
      "samlp": Saml::Kit::Namespaces::PROTOCOL,
    }
    xml_document(actual).xpath(xpath, namespaces).any?
  end

  failure_message do |actual|
    "Expected xpath: #{xpath.inspect} to match in:\n #{xml_pretty_print(actual)}"
  end

  failure_message_when_negated do |actual|
    "Expected xpath: #{xpath.inspect} not to match in:\n #{xml_pretty_print(actual)}"
  end

  def xml_pretty_print(raw_xml)
    xml_document(raw_xml).to_xml(indent: 2)
  end

  def xml_document(raw_xml)
    Nokogiri::XML(raw_xml)
  end
end
