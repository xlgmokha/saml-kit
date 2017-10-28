module Saml
  module Kit
    class Xml
      include ActiveModel::Validations

      attr_reader :raw_xml, :document

      validate :validate_signature
      validate :validate_certificate, if: :signature_element

      def initialize(raw_xml)
        @raw_xml = raw_xml
        @document = Nokogiri::XML(raw_xml, nil, nil, Nokogiri::XML::ParseOptions::STRICT) do |config|
          config.noblanks
        end
      end

      def signature_element
        document.at_xpath('//ds:Signature', Xmldsig::NAMESPACES)
      end

      def certificate
        xpath = '//ds:KeyInfo/ds:X509Data/ds:X509Certificate'
        raw_signature = signature_element.xpath(xpath, Xmldsig::NAMESPACES).text
        OpenSSL::X509::Certificate.new(Base64.decode64(raw_signature))
      end

      private

      def validate_signature
        invalid_signatures.flat_map(&:errors).uniq.each do |error|
          errors.add(error, "is invalid") if error != :signature
        end
      end

      def signed_document
        Xmldsig::SignedDocument.new(document, id_attr: 'ID=$uri or @Id')
      end

      def invalid_signatures
        signed_document.signatures.find_all do |signature|
          !signature.valid?(certificate)
        end
      end

      def validate_certificate(now = Time.current)
        if now < certificate.not_before
          errors.add(:certificate, "Not valid before #{certificate.not_before}")
        end

        if now > certificate.not_after
          errors.add(:certificate, "Not valid after #{certificate.not_after}")
        end
      end
    end
  end
end
