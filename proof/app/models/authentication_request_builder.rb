require 'builder'

class AuthenticationRequestBuilder
  attr_accessor :id, :issued_at, :issuer, :acs_url

  def to_xml(xml = ::Builder::XmlMarkup.new)
    xml.tag!('samlp:AuthnRequest',
      "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
      "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
      ID: id,
      Version: "2.0",
      IssueInstant: issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
      AssertionConsumerServiceURL: acs_url,
    ) do
      xml.tag!('saml:Issuer', issuer)
      xml.tag!('samlp:NameIDPolicy', Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    end
    xml.target!
  end
end
