module Saml
  module Kit
    class IdentityProviderMetadata < Metadata
      def initialize(xml)
        super("IDPSSODescriptor", xml)
      end

      def want_authn_requests_signed
        xpath = "/md:EntityDescriptor/md:#{name}"
        attribute = document.find_by(xpath).attribute("WantAuthnRequestsSigned")
        return true if attribute.nil?
        attribute.text.downcase == "true"
      end

      def single_sign_on_services
        services('SingleSignOnService')
      end

      def single_sign_on_service_for(binding:)
        service_for(binding: binding, type: 'SingleSignOnService')
      end

      def attributes
        document.find_all("/md:EntityDescriptor/md:#{name}/saml:Attribute").map do |item|
          {
            format: item.attribute("NameFormat").try(:value),
            name: item.attribute("Name").value,
          }
        end
      end

      private

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

        def add_single_sign_on_service(url, binding: :http_post)
          @single_sign_on_urls.push(location: url, binding: Bindings.binding_for(binding))
        end

        def add_single_logout_service(url, binding: :http_post)
          @logout_urls.push(location: url, binding: Bindings.binding_for(binding))
        end

        def to_xml
          Signature.sign(sign: sign) do |xml, signature|
            xml.instruct!
            xml.EntityDescriptor entity_descriptor_options do
              signature.template(id)
              xml.IDPSSODescriptor idp_sso_descriptor_options do
                xml.KeyDescriptor use: "signing" do
                  xml.KeyInfo "xmlns": Namespaces::XMLDSIG do
                    xml.X509Data do
                      xml.X509Certificate @configuration.stripped_signing_certificate
                    end
                  end
                end
                logout_urls.each do |item|
                  xml.SingleLogoutService Binding: item[:binding], Location: item[:location]
                end
                name_id_formats.each do |format|
                  xml.NameIDFormat format
                end
                single_sign_on_urls.each do |item|
                  xml.SingleSignOnService Binding: item[:binding], Location: item[:location]
                end
                attributes.each do |attribute|
                  xml.tag! 'saml:Attribute', Name: attribute
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
            WantAuthnRequestsSigned: want_authn_requests_signed,
            protocolSupportEnumeration: Namespaces::PROTOCOL,
          }
        end
      end
    end
  end
end
