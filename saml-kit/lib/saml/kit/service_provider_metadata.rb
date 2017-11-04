module Saml
  module Kit
    class ServiceProviderMetadata < Metadata
      def initialize(xml)
        super("SPSSODescriptor", xml)
      end

      def assertion_consumer_services
        find_all("/md:EntityDescriptor/md:#{name}/md:AssertionConsumerService").map do |item|
          {
            binding: item.attribute("Binding").value,
            location: item.attribute("Location").value,
          }
        end
      end

      def matches?(fingerprint, use: :signing)
        if :signing == use
          sha256 = fingerprint.algorithm(OpenSSL::Digest::SHA256)
          signing_certificates.find do |signing_certificate|
            sha256 == signing_certificate[:fingerprint]
          end
        end
      end

      private

      class Builder
        attr_accessor :id, :entity_id, :acs_urls, :logout_urls, :name_id_formats

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @configuration = configuration
          @entity_id = configuration.issuer
          @acs_urls = []
          @logout_urls = []
          @name_id_formats = [Namespaces::PERSISTENT]
        end

        def add_assertion_consumer_service(url, binding: :post)
          @acs_urls.push(location: url, binding: Namespaces.binding_for(binding))
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
            xml.SPSSODescriptor descriptor_options do
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
              acs_urls.each_with_index do |item, index|
                xml.AssertionConsumerService Binding: item[:binding], Location: item[:location], index: index, isDefault: index == 0 ? true : false
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
            'xmlns': Namespaces::METADATA,
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
