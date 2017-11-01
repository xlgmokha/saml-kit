module Saml
  module Kit
    class ServiceProviderMetadata < Metadata
      def initialize(xml)
        super("SPSSODescriptor", xml)
      end

      def assertion_consumer_services
        xpath = "/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService"
        find_all(xpath).map do |item|
          {
            binding: item.attribute("Binding").value,
            location: item.attribute("Location").value,
          }
        end
      end

      private

      class Builder
        attr_accessor :id, :entity_id, :acs_urls

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @configuration = configuration
          @acs_urls = []
        end

        def add_acs_url(url, binding: :post)
          @acs_urls.push(location: url, binding: binding_namespace_for(binding))
        end

        def to_xml
          signature = Signature.new(id)
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.tag! 'md:EntityDescriptor', entity_descriptor_options do
            signature.template(xml)
            xml.tag! "md:SPSSODescriptor", descriptor_options do
              xml.tag! "md:NameIDFormat", Namespaces::Formats::NameId::PERSISTENT
              acs_urls.each_with_index do |item, index|
                xml.tag! "md:AssertionConsumerService", {
                  Binding: item[:binding],
                  Location: item[:location],
                  index: index,
                  isDefault: index == 0 ? true : false,
                }
              end
              xml.tag! "md:KeyDescriptor", use: "signing" do
                xml.tag! "ds:KeyInfo", "xmlns:ds": Saml::Kit::Signature::XMLDSIG do
                  xml.tag! "ds:X509Data" do
                    xml.tag! "ds:X509Certificate", @configuration.stripped_signing_certificate
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

        def binding_namespace_for(binding)
          if :post == binding
            Namespaces::Bindings::POST
          else
            Namespaces::Bindings::HTTP_REDIRECT
          end
        end
      end
    end
  end
end
