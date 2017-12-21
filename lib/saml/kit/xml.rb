module Saml
  module Kit
    class Xml # :nodoc:
      include ActiveModel::Validations
      NAMESPACES = {
        "NameFormat": Namespaces::ATTR_SPLAT,
        "ds": Namespaces::XMLDSIG,
        "md": Namespaces::METADATA,
        "saml": Namespaces::ASSERTION,
        "samlp": Namespaces::PROTOCOL,
      }.freeze

      validate :validate_signatures
      validate :validate_certificates

      def initialize(raw_xml)
        @raw_xml = raw_xml
        @document = Nokogiri::XML(raw_xml)
      end

      # Returns the first XML node found by searching the document with the provided XPath.
      #
      # @param xpath [String] the XPath to use to search the document
      def find_by(xpath)
        document.at_xpath(xpath, NAMESPACES)
      end

      # Returns all XML nodes found by searching the document with the provided XPath.
      #
      # @param xpath [String] the XPath to use to search the document
      def find_all(xpath)
        document.search(xpath, NAMESPACES)
      end

      # Return the XML document as a [String].
      #
      # @param pretty [Boolean] return the XML string in a human readable format if true.
      def to_xml(pretty: true)
        pretty ? document.to_xml(indent: 2) : raw_xml
      end

      private

      attr_reader :raw_xml, :document

      def validate_signatures
        invalid_signatures.flat_map(&:errors).uniq.each do |error|
          errors.add(error, "is invalid")
        end
      end

      def invalid_signatures
        signed_document = Xmldsig::SignedDocument.new(document, id_attr: 'ID=$uri or @Id')
        signed_document.signatures.find_all do |signature|
          x509_certificates.all? do |certificate|
            !signature.valid?(certificate)
          end
        end
      end

      def validate_certificates(now = Time.current)
        return unless document.at_xpath('//ds:Signature', Xmldsig::NAMESPACES).present?

        x509_certificates.each do |certificate|
          if now < certificate.not_before
            errors.add(:certificate, "Not valid before #{certificate.not_before}")
          end

          if now > certificate.not_after
            errors.add(:certificate, "Not valid after #{certificate.not_after}")
          end
        end
      end

      def x509_certificates
        xpath = "//ds:KeyInfo/ds:X509Data/ds:X509Certificate"
        document.search(xpath, Xmldsig::NAMESPACES).map do |item|
          Certificate.to_x509(item.text)
        end
      end
    end
  end
end
