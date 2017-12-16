module Saml
  module Kit
    module Builders
      class ServiceProviderMetadata
        include Saml::Kit::Templatable
        extend Forwardable
        attr_accessor :acs_urls, :logout_urls, :name_id_formats
        attr_accessor :want_assertions_signed
        attr_reader :configuration
        attr_reader :metadata
        def_delegators :metadata, :id, :id=, :entity_id, :entity_id=, :organization_name, :organization_name=, :organization_url, :organization_url=, :contact_email, :contact_email=, :to_xml

        def initialize(configuration: Saml::Kit.configuration)
          @acs_urls = []
          @configuration = configuration
          @logout_urls = []
          @name_id_formats = [Namespaces::PERSISTENT]
          @want_assertions_signed = true
          @metadata = Saml::Kit::Builders::Metadata.new(configuration: configuration)
          @metadata.service_provider = self
        end

        def add_assertion_consumer_service(url, binding: :http_post)
          @acs_urls.push(location: url, binding: Bindings.binding_for(binding))
        end

        def add_single_logout_service(url, binding: :http_post)
          @logout_urls.push(location: url, binding: Bindings.binding_for(binding))
        end

        def build
          Saml::Kit::ServiceProviderMetadata.new(to_xml)
        end

        private

        def entity_descriptor_options
          {
            'xmlns': Namespaces::METADATA,
            ID: id,
            entityID: entity_id,
          }
        end

        def descriptor_options
          {
            AuthnRequestsSigned: sign?,
            WantAssertionsSigned: want_assertions_signed,
            protocolSupportEnumeration: Namespaces::PROTOCOL,
          }
        end
      end
    end
  end
end
