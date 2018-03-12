# frozen_string_literal: true

xml.instruct!
xml.Response response_options do
  xml.Issuer(issuer, xmlns: Saml::Kit::Namespaces::ASSERTION)
  signature_for(reference_id: id, xml: xml)
  xml.Status do
    xml.StatusCode Value: status_code
    xml.StatusMessage(status_message) if status_message.present?
  end
  render assertion, xml: xml
end
