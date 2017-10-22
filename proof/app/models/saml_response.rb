require 'builder'

class SamlResponse
  def initialize(xml)
    @xml = xml
  end

  def to_xml
    @xml
  end

  def self.for(user, authentication_request)
    builder = Builder.new(user, authentication_request)
    builder.build
  end

  class Builder
    attr_reader :user, :request, :id

    def initialize(user, request)
      @user = user
      @request = request
      @id = SecureRandom.uuid
    end

    def to_xml
      xml = ::Builder::XmlMarkup.new
      options = {
        "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
        "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
        ID: "_#{id}",
        Version: "2.0",
        IssueInstant: Time.now.utc.iso8601,
        Destination: request.acs_url,
        InResponseTo: request.id,
      }
      xml.tag! "samlp:Response", options do |response|
      end
      xml.target!
    end

    def build
      SamlResponse.new(to_xml)
    end
  end
end
