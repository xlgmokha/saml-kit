module Saml
  module Kit
    class IdentityProviderMetadata < Metadata
      def initialize(xml)
        super("IDPSSODescriptor", xml)
      end

      def single_sign_on_services
        xpath = "/md:EntityDescriptor/md:#{name}/md:SingleSignOnService"
        find_all(xpath).map do |item|
          { binding: item.attribute("Binding").value, location: item.attribute("Location").value }
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

      private

      class Builder
        attr_accessor :id, :organization_name, :organization_url, :contact_email, :entity_id, :attributes, :name_id_formats
        attr_reader :logout_urls, :single_sign_on_urls

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @entity_id = configuration.issuer
          @attributes = []
          @name_id_formats = [Namespaces::PERSISTENT]
          @single_sign_on_urls = []
          @logout_urls = []
        end

        def add_single_sign_on_service(url, binding: :post)
          @single_sign_on_urls.push(location: url, binding: Namespaces.binding_for(binding))
        end

        def add_single_logout_service(url, binding: :post)
          @logout_urls.push(location: url, binding: Namespaces.binding_for(binding))
        end

        def to_xml
          signature = Signature.new(id)
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.EntityDescriptor entity_descriptor_options do
            signature.template(xml)
            xml.IDPSSODescriptor protocolSupportEnumeration: Namespaces::PROTOCOL do
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
          signature.finalize(xml)
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
      end
    end
  end
end
