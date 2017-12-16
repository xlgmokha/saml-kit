module Saml
  module Kit
    module Builders
      class Metadata
        include Templatable

        attr_reader :id
        attr_reader :entity_id
        attr_reader :configuration
        attr_reader :service_provider
        attr_reader :identity_provider

        def initialize(configuration: Saml::Kit.configuration)
          @id = Id.generate
          @entity_id = configuration.issuer
          @configuration = configuration
        end

        def build_service_provider
          @service_provider = Saml::Kit::ServiceProviderMetadata.builder(configuration: configuration) do |x|
            yield x if block_given?
          end
        end

        def build_identity_provider
          @identity_provider = Saml::Kit::IdentityProviderMetadata.builder(configuration: configuration) do |x|
            yield x if block_given?
          end
        end

        def build
          Saml::Kit::Metadata.from(to_xml)
        end

        private

        def entity_descriptor_options
          {
            'xmlns': Namespaces::METADATA,
            'xmlns:ds': Namespaces::XMLDSIG,
            'xmlns:saml': Namespaces::ASSERTION,
            ID: id,
            entityID: entity_id,
          }
        end
      end
    end
  end
end
