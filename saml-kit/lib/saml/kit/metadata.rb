module Saml
  module Kit
    class Metadata
      include ActiveModel::Validations

      METADATA_XSD = File.expand_path("./xsd/saml-schema-metadata-2.0.xsd", File.dirname(__FILE__)).freeze
      NAMESPACES = {
        "NameFormat": Namespaces::Formats::Attr::SPLAT,
        "ds": Namespaces::SIGNATURE,
        "md": Namespaces::METADATA,
        "saml": Namespaces::ASSERTION,
      }.freeze

      validates_presence_of :metadata
      validate :must_contain_descriptor
      validate :must_match_xsd
      validate :must_have_valid_signature

      attr_reader :xml, :descriptor_name

      def initialize(descriptor_name, xml)
        @descriptor_name = descriptor_name
        @xml = xml
      end

      def entity_id
        find_by("/md:EntityDescriptor/@entityID").value
      end

      def name_id_formats
        find_all("/md:EntityDescriptor/md:#{descriptor_name}/md:NameIDFormat").map(&:text)
      end

      def certificates
        xpath = "/md:EntityDescriptor/md:#{descriptor_name}/md:KeyDescriptor"
        find_all(xpath).map do |item|
          cert = item.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NAMESPACES).text
          {
            text: cert,
            fingerprint: fingerprint_for(cert, OpenSSL::Digest::SHA256),
            use: item.attribute('use').value,
          }
        end
      end

      def encryption_certificates
        certificates.find_all { |x| x[:use] == "encryption" }
      end

      def signing_certificates
        certificates.find_all { |x| x[:use] == "signing" }
      end

      def single_logout_services
        xpath = "/md:EntityDescriptor/md:#{descriptor_name}/md:SingleLogoutService"
        find_all(xpath).map do |item|
          {
            binding: item.attribute("Binding").value,
            location: item.attribute("Location").value,
          }
        end
      end

      def to_xml
        @xml
      end

      private

      def document
        @document ||= Nokogiri::XML(@xml)
      end

      def find_by(xpath)
        document.at_xpath(xpath, NAMESPACES)
      end

      def find_all(xpath)
        document.search(xpath, NAMESPACES)
      end

      def fingerprint_for(value, algorithm)
        x509 = OpenSSL::X509::Certificate.new(Base64.decode64(value))
        pretty_fingerprint(algorithm.new.hexdigest(x509.to_der))
      end

      def pretty_fingerprint(fingerprint)
        fingerprint.upcase.scan(/../).join(":")
      end

      def metadata
        find_by("/md:EntityDescriptor/md:#{descriptor_name}").present?
      end

      def must_contain_descriptor
        errors[:metadata] << error_message(:invalid) unless metadata
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

        unless valid_signature?
          errors[:metadata] << error_message(:invalid_signature)
        end
      end

      def valid_signature?
        xml = Saml::Kit::Xml.new(to_xml)
        result = xml.valid?
        xml.errors.each do |error|
          errors[:metadata] << error
        end
        result
      end

      def error_message(key)
        I18n.translate(key, scope: "saml/kit.errors.#{descriptor_name}")
      end
    end
  end
end
