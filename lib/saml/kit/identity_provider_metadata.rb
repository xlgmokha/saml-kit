module Saml
  module Kit
    # This class is used to parse the IDPSSODescriptor from a SAML metadata document.
    #
    #  raw_xml = <<-XML
    #  <?xml version="1.0" encoding="UTF-8"?>
    #  <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_cfa24e2f-0ec0-4ee3-abb8-b2fcfe394c1c" entityID="">
    #    <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    #      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/logout"/>
    #      <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    #      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/login"/>
    #      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://www.example.com/login"/>
    #      <saml:Attribute Name="id"/>
    #    </IDPSSODescriptor>
    #  </EntityDescriptor>
    #  XML
    #
    #  metadata = Saml::Kit::IdentityProviderMetadata.new(raw_xml)
    #  puts metadata.entity_id
    #
    # It can also be used to generate IDP metadata.
    #
    #   metadata = Saml::Kit::IdentityProviderMetadata.build do |builder|
    #     builder.entity_id = "my-entity-id"
    #   end
    #   puts metadata.to_xml
    #
    # For more details on generating metadata see {Saml::Kit::Metadata}.
    #
    # Example:
    #
    # {include:file:spec/examples/identity_provider_metadata_spec.rb}
    class IdentityProviderMetadata < Metadata
      def initialize(xml)
        super('IDPSSODescriptor', xml)
      end

      # Returns the IDPSSODescriptor/@WantAuthnRequestsSigned attribute.
      def want_authn_requests_signed
        xpath = "/md:EntityDescriptor/md:#{name}"
        attribute = at_xpath(xpath).attribute('WantAuthnRequestsSigned')
        return true if attribute.nil?
        attribute.text.casecmp('true').zero?
      end

      # Returns each of the SingleSignOnService elements.
      def single_sign_on_services
        services('SingleSignOnService')
      end

      # Returns a SingleSignOnService elements with the specified binding.
      #
      # @param binding [Symbol] `:http_post` or `:http_redirect`.
      def single_sign_on_service_for(binding:)
        service_for(binding: binding, type: 'SingleSignOnService')
      end

      # Returns each of the Attributes in the metadata.
      def attributes
        search("/md:EntityDescriptor/md:#{name}/saml:Attribute").map do |item|
          {
            format: item.attribute('NameFormat').try(:value),
            name: item.attribute('Name').value,
          }
        end
      end

      # Creates a AuthnRequest document for the specified binding.
      #
      # @param binding [Symbol] `:http_post` or `:http_redirect`.
      # @param relay_state [Object] The RelayState to include the returned SAML params.
      # @param configuration [Saml::Kit::Configuration] the configuration to use for generating the request.
      # @return [Array] The url and saml params encoded using the rules for the specified binding.
      def login_request_for(binding:, relay_state: nil, configuration: Saml::Kit.configuration)
        builder = Saml::Kit::AuthenticationRequest.builder(configuration: configuration) do |x|
          x.embed_signature = want_authn_requests_signed
          yield x if block_given?
        end
        request_binding = single_sign_on_service_for(binding: binding)
        request_binding.serialize(builder, relay_state: relay_state)
      end

      # @!visibility private
      def self.builder_class
        Saml::Kit::Builders::IdentityProviderMetadata
      end
    end
  end
end
