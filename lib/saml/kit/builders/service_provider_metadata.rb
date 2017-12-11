module Saml
  module Kit
    module Builders
      class ServiceProviderMetadata
        include Saml::Kit::Templatable
        attr_accessor :id, :entity_id, :acs_urls, :logout_urls, :name_id_formats, :sign
        attr_accessor :organization_name, :organization_url, :contact_email
        attr_accessor :want_assertions_signed
        attr_reader :configuration

        def initialize(configuration = Saml::Kit.configuration)
          @acs_urls = []
          @configuration = configuration
          @entity_id = configuration.issuer
          @id = Id.generate
          @logout_urls = []
          @name_id_formats = [Namespaces::PERSISTENT]
          @sign = true
          @want_assertions_signed = true
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
            AuthnRequestsSigned: sign,
            WantAssertionsSigned: want_assertions_signed,
            protocolSupportEnumeration: Namespaces::PROTOCOL,
          }
        end
      end
    end
  end
end
