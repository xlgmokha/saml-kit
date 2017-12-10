module Saml
  module Kit
    module Builders
      class IdentityProviderMetadata
        include Saml::Kit::Templatable
        attr_accessor :id, :organization_name, :organization_url, :contact_email, :entity_id, :attributes, :name_id_formats
        attr_accessor :want_authn_requests_signed, :sign
        attr_reader :logout_urls, :single_sign_on_urls
        attr_reader :template_name, :configuration

        def initialize(configuration = Saml::Kit.configuration)
          @attributes = []
          @configuration = configuration
          @entity_id = configuration.issuer
          @id = Id.generate
          @logout_urls = []
          @name_id_formats = [Namespaces::PERSISTENT]
          @sign = true
          @single_sign_on_urls = []
          @template_name = 'identity_provider_metadata'
          @want_authn_requests_signed = true
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
            'xmlns:ds': Namespaces::XMLDSIG,
            'xmlns:saml': Namespaces::ASSERTION,
            ID: id,
            entityID: entity_id,
          }
        end

        def idp_sso_descriptor_options
          {
            WantAuthnRequestsSigned: want_authn_requests_signed,
            protocolSupportEnumeration: Namespaces::PROTOCOL,
          }
        end
      end
    end
  end
end
