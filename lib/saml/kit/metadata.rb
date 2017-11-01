module Saml
  module Kit
    class Metadata
      NAMESPACES = {
        "NameFormat": Namespaces::Formats::Attr::SPLAT,
        "ds": Namespaces::SIGNATURE,
        "md": Namespaces::METADATA,
        "saml": Namespaces::ASSERTION,
      }.freeze

      attr_reader :xml, :descriptor_name

      def initialize(descriptor_name, xml)
        @descriptor_name = descriptor_name
        @xml = xml
      end

      def certificates
        xpath = "/md:EntityDescriptor/md:#{descriptor_name}/md:KeyDescriptor"
        find_all(xpath).map do |item|
          cert = item.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NAMESPACES).text
          {
            fingerprint: fingerprint_for(cert, OpenSSL::Digest::SHA256),
            text: cert,
            use: item.attribute('use').value,
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
    end
  end
end
