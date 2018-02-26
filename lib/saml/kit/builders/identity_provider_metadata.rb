# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/identity_provider_metadata.builder}
      # {include:file:spec/saml/builders/identity_provider_metadata_spec.rb}
      class IdentityProviderMetadata
        include XmlTemplatable
        extend Forwardable
        attr_accessor :attributes, :name_id_formats
        attr_accessor :want_authn_requests_signed
        attr_reader :logout_urls, :single_sign_on_urls
        attr_reader :configuration
        attr_reader :metadata
        def_delegators :metadata, :id, :id=, :entity_id, :entity_id=, :organization_name, :organization_name=, :organization_url, :organization_url=, :contact_email, :contact_email=, :to_xml

        def initialize(configuration: Saml::Kit.configuration)
          @attributes = []
          @configuration = configuration
          @entity_id = configuration.entity_id
          @id = ::Xml::Kit::Id.generate
          @logout_urls = []
          @name_id_formats = [Namespaces::PERSISTENT]
          @single_sign_on_urls = []
          @want_authn_requests_signed = true
          @metadata = Saml::Kit::Builders::Metadata.new(configuration: configuration)
          @metadata.identity_provider = self
        end

        def add_single_sign_on_service(url, binding: :http_post)
          @single_sign_on_urls.push(location: url, binding: Bindings.binding_for(binding))
        end

        def add_single_logout_service(url, binding: :http_post)
          @logout_urls.push(location: url, binding: Bindings.binding_for(binding))
        end

        def build
          Saml::Kit::IdentityProviderMetadata.new(to_xml)
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

        def descriptor_options
          {
            WantAuthnRequestsSigned: want_authn_requests_signed,
            protocolSupportEnumeration: Namespaces::PROTOCOL,
          }
        end
      end
    end
  end
end
