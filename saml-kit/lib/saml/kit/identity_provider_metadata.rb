module Saml
  module Kit
    class IdentityProviderMetadata
      NAMESPACES = {
        "NameFormat": Namespaces::Formats::Attr::SPLAT,
        "ds": Namespaces::SIGNATURE,
        "md": Namespaces::METADATA,
        "saml": Namespaces::ASSERTION,
      }.freeze
      METADATA_XSD = File.expand_path("./xsd/saml-schema-metadata-2.0.xsd", File.dirname(__FILE__)).freeze

      include ActiveModel::Validations
      validates_presence_of :metadata
      validate :must_contain_idp_descriptor
      validate :must_match_xsd
      validate :must_have_valid_signature

      def initialize(xml)
        @xml = xml
      end

      def entity_id
        find_by("/md:EntityDescriptor/@entityID").value
      end

      def name_id_formats
        find_all("/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat").map(&:text)
      end

      def single_sign_on_services
        xpath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService"
        find_all(xpath).map do |item|
          { binding: item.attribute("Binding").value, location: item.attribute("Location").value }
        end
      end

      def single_logout_services
        xpath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService"
        find_all(xpath).map do |item|
          { binding: item.attribute("Binding").value, location: item.attribute("Location").value }
        end
      end

      def certificates
        xpath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor"
        find_all(xpath).map do |item|
          cert = Base64.decode64(item.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NAMESPACES).text)
          {
            fingerprint: fingerprint_for(cert),
            use: item.attribute('use').value,
            value: cert,
          }
        end
      end

      def attributes
        find_all("/md:EntityDescriptor/md:IDPSSODescriptor/saml:Attribute").map do |item|
          {
            format: item.attribute("NameFormat").value,
            friendly_name: item.attribute("FriendlyName").value,
            name: item.attribute("Name").value,
          }
        end
      end

      def to_xml
        @xml
      end

      private

      def error_message(key)
        I18n.translate(key, scope: 'saml/kit.errors.identity_provider_metadata')
      end

      def metadata
        find_by('/md:EntityDescriptor/md:IDPSSODescriptor').present?
      end

      def must_contain_idp_descriptor
        errors[:metadata] << error_message('metadata.invalid_idp') unless metadata
      end

      def must_match_xsd
        Dir.chdir(File.dirname(METADATA_XSD)) do
          xsd = Nokogiri::XML::Schema(IO.read(METADATA_XSD))
          xsd.validate(document).each do |error|
            errors[:metadata] << error.message
          end
        end
      end

      def must_have_valid_signature
        return if to_xml.blank?
        errors[:metadata] << error_message('metadata.invalid_signature') unless valid_signature?
      end

      def valid_signature?
        xml = Saml::Kit::Xml.new(to_xml)
        result = xml.valid?
        xml.errors.each do |error|
          errors[:metadata] << error
        end
        result
      end

      def fingerprint_for(value)
        x509 = OpenSSL::X509::Certificate.new(value)
        OpenSSL::Digest::SHA256.new.hexdigest(x509.to_der).upcase.scan(/../).join(":")
      end

      def document
        @document ||= Nokogiri::XML(@xml)
      end

      def find_by(xpath)
        document.at_xpath(xpath, NAMESPACES)
      end

      def find_all(xpath)
        document.search(xpath, NAMESPACES)
      end

      class Builder
        attr_accessor :id, :organization_name, :organization_url, :contact_email, :entity_id, :single_sign_on_location, :single_logout_location, :attributes

        def initialize
          @id = SecureRandom.uuid
          @attributes = []
        end

        def to_xml
          signature = Signature.new(id)
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.EntityDescriptor entity_descriptor_options do
            signature.template(xml)
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
          signature.finalize(xml)
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
            ID: id,
            entityID: entity_id,
          }
        end
      end
    end
  end
end
