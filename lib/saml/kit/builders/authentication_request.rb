module Saml
  module Kit
    module Builders
      class AuthenticationRequest
        attr_accessor :id, :now, :issuer, :assertion_consumer_service_url, :name_id_format, :sign, :destination
        attr_accessor :version

        def initialize(configuration: Saml::Kit.configuration, sign: true)
          @id = SecureRandom.uuid
          @issuer = configuration.issuer
          @name_id_format = Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = "2.0"
          @sign = sign
        end

        def to_xml
          Signature.sign(sign: sign) do |xml, signature|
            xml.tag!('samlp:AuthnRequest', request_options) do
              xml.tag!('saml:Issuer', issuer)
              signature.template(id)
              xml.tag!('samlp:NameIDPolicy', Format: name_id_format)
            end
          end
        end

        def build
          Saml::Kit::AuthenticationRequest.new(to_xml)
        end

        private

        def request_options
          options = {
            "xmlns:samlp" => Namespaces::PROTOCOL,
            "xmlns:saml" => Namespaces::ASSERTION,
            ID: "_#{id}",
            Version: version,
            IssueInstant: now.utc.iso8601,
            Destination: destination,
          }
          options[:AssertionConsumerServiceURL] = assertion_consumer_service_url if assertion_consumer_service_url.present?
          options
        end
      end
    end
  end
end
