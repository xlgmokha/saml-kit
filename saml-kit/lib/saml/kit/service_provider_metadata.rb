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

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @configuration = configuration
        end

        def to_xml
          signature = Signature.new(id)
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.tag! 'md:EntityDescriptor', entity_descriptor_options do
            signature.template(xml)
            xml.tag! "md:SPSSODescriptor", descriptor_options do
              xml.tag! "md:NameIDFormat", Namespaces::Formats::NameId::PERSISTENT
              xml.tag! "md:AssertionConsumerService", Binding: Namespaces::Bindings::POST, Location: acs_url, index: "0", isDefault: "true"
              xml.tag! "md:KeyDescriptor", use: "signing" do
                xml.tag! "ds:KeyInfo", "xmlns:ds": Saml::Kit::Signature::XMLDSIG do
                  xml.tag! "ds:X509Data" do
                    xml.tag! "ds:X509Certificate", @configuration.stripped_certificate
                  end
                end
              end
            end
          end
          signature.finalize(xml)
        end

        def build
          ServiceProviderMetadata.new(to_xml)
        end

        private

        def entity_descriptor_options
          {
            'xmlns:md': Namespaces::METADATA,
            ID: id,
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
