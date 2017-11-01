module Saml
  module Kit
    class AuthenticationRequest
      def initialize(xml, registry = ServiceProviderRegistry.new)
        @xml = xml
        @registry = registry
        @hash = Hash.from_xml(@xml)
      end

      def id
        @hash['AuthnRequest']['ID']
      end

      def acs_url
        @hash['AuthnRequest']['AssertionConsumerServiceURL']
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
        Response::Builder.new(user, self).build
      end

      class Builder
        attr_accessor :id, :issued_at, :issuer, :acs_url

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @issued_at = Time.now.utc
          @acs_url = configuration.acs_url
          @issuer = configuration.issuer
        end

        def to_xml(xml = ::Builder::XmlMarkup.new)
          signature = Signature.new(id)
          xml.tag!('samlp:AuthnRequest',
                   "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
                   "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
                   ID: id,
                   Version: "2.0",
                   IssueInstant: issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   AssertionConsumerServiceURL: acs_url,
                  ) do
            signature.template(xml)
            xml.tag!('saml:Issuer', issuer)
            xml.tag!('samlp:NameIDPolicy', Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
          end
          signature.finalize(xml)
        end

        def build
          AuthenticationRequest.new(to_xml)
        end
      end
    end
  end
end
