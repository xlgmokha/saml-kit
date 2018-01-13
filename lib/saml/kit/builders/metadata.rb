module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/metadata.builder}
      # {include:file:spec/saml/builders/metadata_spec.rb}
      class Metadata
        include XmlTemplatable

        attr_accessor :entity_id
        attr_accessor :id
        attr_accessor :identity_provider
        attr_accessor :organization_name, :organization_url, :contact_email
        attr_accessor :service_provider
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration)
          @id = ::Xml::Kit::Id.generate
          @entity_id = configuration.entity_id
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
            'xmlns:ds': ::Xml::Kit::Namespaces::XMLDSIG,
            'xmlns:saml': Namespaces::ASSERTION,
            ID: id,
            entityID: entity_id,
          }
        end
      end
    end
  end
end
