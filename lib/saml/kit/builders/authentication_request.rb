module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/authentication_request.builder}
      # {include:file:spec/saml/builders/authentication_request_spec.rb}
      class AuthenticationRequest
        include XmlTemplatable
        attr_accessor :id, :now, :issuer, :assertion_consumer_service_url, :name_id_format, :destination
        attr_accessor :version
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration)
          @configuration = configuration
          @id = ::Xml::Kit::Id.generate
          @issuer = configuration.issuer
          @name_id_format = Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = "2.0"
        end

        # @deprecated Use {#assertion_consumer_service_url} instead of this method.
        def acs_url
          Saml::Kit.deprecate("acs_url is deprecated. Use assertion_consumer_service_url instead")
          self.assertion_consumer_service_url
        end

        # @deprecated Use {#assertion_consumer_service_url=} instead of this method.
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
          if assertion_consumer_service_url.present?
            options[:AssertionConsumerServiceURL] = assertion_consumer_service_url
          end
          options
        end
      end
    end
  end
end
