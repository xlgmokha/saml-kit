require 'builder'

class AuthenticationRequest
  attr_reader :id, :issued_at

  def initialize(configuration = Configuration.new)
    @id = SecureRandom.uuid
    @issued_at = Time.now.utc
    @configuration = configuration
  end

  def to_xml(xml = ::Builder::XmlMarkup.new)
    xml.tag!('samlp:AuthnRequest',
      "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
      "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
      ID: id,
      Version: "2.0",
      IssueInstant: issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
      AssertionConsumerServiceURL: @configuration.acs_url,
    ) do
      xml.tag!('saml:Issuer', @configuration.issuer)
      xml.tag!('samlp:NameIDPolicy', Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    end
    xml.target!
  end
end
