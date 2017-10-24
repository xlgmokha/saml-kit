module Saml
  module Kit
    class IdentityProviderMetadata
      def initialize(xml)
        @xml = xml
      end

      def to_xml
        @xml
      end

      class Builder
        attr_accessor :id, :organization_name, :organization_url, :contact_email, :entity_id, :single_sign_on_location, :single_logout_location, :attributes

        def initialize
          @id = SecureRandom.uuid
          @attributes = []
        end

        def to_xml
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.EntityDescriptor entity_descriptor_options do
            xml.IDPSSODescriptor protocolSupportEnumeration: Namespaces::PROTOCOL do
              xml.NameIDFormat Namespaces::Formats::NameId::PERSISTENT
              xml.SingleLogoutService Binding: Namespaces::Bindings::POST, Location: single_logout_location
              xml.SingleSignOnService Binding: Namespaces::Bindings::HTTP_REDIRECT, Location: single_sign_on_location
              attributes.each do |attribute|
                xml.tag! 'saml:Attribute', NameFormat: Namespaces::Formats::Attr::URI, Name: attribute, FriendlyName: attribute
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
          xml.target!
        end

        def build
          IdentityProviderMetadata.new(to_xml)
        end

        private

        def entity_descriptor_options
          {
            'xmlns': Namespaces::METADATA,
            'xmlns:ds': Namespaces::SIGNATURE,
            'xmlns:saml': Namespaces::ASSERTION,
            ID: "_#{id}",
            entityID: entity_id,
          }
        end
      end
    end
  end
end
