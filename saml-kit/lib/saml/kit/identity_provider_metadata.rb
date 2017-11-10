module Saml
  module Kit
    class IdentityProviderMetadata < Metadata
      def initialize(xml)
        super("IDPSSODescriptor", xml)
      end

      def want_authn_requests_signed
        xpath = "/md:EntityDescriptor/md:#{name}"
        attribute = find_by(xpath).attribute("WantAuthnRequestsSigned")
        return true if attribute.nil?
        attribute.text.downcase == "true"
      end

      def single_sign_on_services
        xpath = "/md:EntityDescriptor/md:#{name}/md:SingleSignOnService"
        find_all(xpath).map do |item|
          {
            binding: item.attribute("Binding").value,
            location: item.attribute("Location").value,
          }
        end
      end

      def single_sign_on_service_for(binding:)
        binding = Saml::Kit::Namespaces.binding_for(binding)
        single_sign_on_services.find do |item|
          item[:binding] == binding
        end
      end

      def attributes
        find_all("/md:EntityDescriptor/md:#{name}/saml:Attribute").map do |item|
          {
            format: item.attribute("NameFormat").value,
            friendly_name: item.attribute("FriendlyName").value,
            name: item.attribute("Name").value,
          }
        end
      end

      def build_authentication_request
        builder = AuthenticationRequest::Builder.new(sign: want_authn_requests_signed)
        yield builder if block_given?
        builder.build
      end

      class Builder
        attr_accessor :id, :organization_name, :organization_url, :contact_email, :entity_id, :attributes, :name_id_formats
        attr_accessor :want_authn_requests_signed, :sign
        attr_reader :logout_urls, :single_sign_on_urls

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @entity_id = configuration.issuer
          @attributes = []
          @name_id_formats = [Namespaces::PERSISTENT]
          @single_sign_on_urls = []
          @logout_urls = []
          @configuration = configuration
          @sign = true
          @want_authn_requests_signed = true
        end

        def add_single_sign_on_service(url, binding: :post)
          @single_sign_on_urls.push(location: url, binding: Namespaces.binding_for(binding))
        end

        def add_single_logout_service(url, binding: :post)
          @logout_urls.push(location: url, binding: Namespaces.binding_for(binding))
        end

        def to_xml
          Signature.sign(id, sign: sign) do |xml, signature|
            xml.instruct!
            xml.EntityDescriptor entity_descriptor_options do
              signature.template(xml)
              xml.IDPSSODescriptor idp_sso_descriptor_options do
                xml.KeyDescriptor use: "signing" do
                  xml.KeyInfo "xmlns": Namespaces::XMLDSIG do
                    xml.X509Data do
                      xml.X509Certificate @configuration.stripped_signing_certificate
                    end
                  end
                end
                name_id_formats.each do |format|
                  xml.NameIDFormat format
                end
                logout_urls.each do |item|
                  xml.SingleLogoutService Binding: item[:binding], Location: item[:location]
                end
                single_sign_on_urls.each do |item|
                  xml.SingleSignOnService Binding: item[:binding], Location: item[:location]
                end
                attributes.each do |attribute|
                  xml.tag! 'saml:Attribute', NameFormat: Namespaces::URI, Name: attribute, FriendlyName: attribute
                end
              end
              xml.Organization do
                xml.OrganizationName organization_name, 'xml:lang': "en"
                xml.OrganizationDisplayName organization_name, 'xml:lang': "en"
                xml.OrganizationURL organization_url, 'xml:lang': "en"
              end
              xml.ContactPerson contactType: "technical" do
                xml.Company "mailto:#{contact_email}"
              end
            end
          end
        end

        def build
          IdentityProviderMetadata.new(to_xml)
        end

        private

        def entity_descriptor_options
          {
            'xmlns': Namespaces::METADATA,
            'xmlns:ds': Namespaces::XMLDSIG,
            'xmlns:saml': Namespaces::ASSERTION,
            ID: "_#{id}",
            entityID: entity_id,
          }
        end

        def idp_sso_descriptor_options
          {
            protocolSupportEnumeration: Namespaces::PROTOCOL,
            WantAuthnRequestsSigned: want_authn_requests_signed
          }
        end
      end
    end
  end
end
