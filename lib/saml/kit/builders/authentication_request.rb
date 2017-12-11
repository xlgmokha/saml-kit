module Saml
  module Kit
    module Builders
      class AuthenticationRequest
        include Saml::Kit::Templatable
        attr_accessor :id, :now, :issuer, :assertion_consumer_service_url, :name_id_format, :sign, :destination
        attr_accessor :version
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration, sign: true)
          @configuration = configuration
          @id = Id.generate
          @issuer = configuration.issuer
          @name_id_format = Namespaces::PERSISTENT
          @now = Time.now.utc
          @sign = sign
          @version = "2.0"
        end

        def acs_url
          Saml::Kit.deprecate("acs_url is deprecated. Use assertion_consumer_service_url instead")
          self.assertion_consumer_service_url
        end

        def acs_url=(value)
          Saml::Kit.deprecate("acs_url= is deprecated. Use assertion_consumer_service_url= instead")
          self.assertion_consumer_service_url = value
        end

        def build
          Saml::Kit::AuthenticationRequest.new(to_xml)
        end

        private

        def request_options
          options = {
            "xmlns:samlp" => Namespaces::PROTOCOL,
            "xmlns:saml" => Namespaces::ASSERTION,
            ID: id,
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
