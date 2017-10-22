require 'builder'

class AuthenticationRequest
  def initialize(xml, registry = ServiceProviderRegistry.new)
    @xml = xml
    @registry = registry
    @hash = Hash.from_xml(@xml)
  end

  def issuer
    @hash['AuthnRequest']['Issuer']
  end

  def valid?
    @registry.registered?(issuer)
  end

  def to_xml
    @xml
  end

  def response_for(user)
    SamlResponse.for(user, self)
  end

  class Builder
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
end
