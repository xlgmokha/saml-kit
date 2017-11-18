RSpec::Matchers.define :have_xpath do |xpath|
  SAML_NAMESPACES = {
    'saml' => Saml::Kit::Namespaces::ASSERTION,
    'samlp' => Saml::Kit::Namespaces::PROTOCOL,
  }.freeze

  match do |actual|
    xml_document(actual).xpath(xpath, SAML_NAMESPACES).any?
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