module Saml
  module Kit
    class ServiceProviderMetadata
      def initialize(xml)
        @xml = xml
      end

      def to_xml
        @xml
      end

      class Builder
        attr_accessor :id, :entity_id, :acs_url

        def initialize
          @id = SecureRandom.uuid
        end

        def to_xml
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.EntityDescriptor entity_descriptor_options do
            xml.tag! "md:SPSSODescriptor", descriptor_options do
              xml.tag! "md:NameIDFormat", Namespaces::Formats::NameId::PERSISTENT
              xml.tag! "md:AssertionConsumerService", Binding: Namespaces::Bindings::POST, Location: acs_url, index: "0", isDefault: "true"
            end
          end
          xml.target!
        end

        def build
          ServiceProviderMetadata.new(to_xml)
        end

        private

        def entity_descriptor_options
          {
            'xmlns:md': Namespaces::METADATA,
            ID: "_#{id}",
            entityID: entity_id,
          }
        end

        def descriptor_options
          {
            AuthnRequestsSigned: "true",
            WantAssertionsSigned: "true",
            protocolSupportEnumeration: Namespaces::PROTOCOL,
          }
        end
      end
    end
  end
end
