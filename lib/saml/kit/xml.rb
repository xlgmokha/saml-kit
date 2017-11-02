module Saml
  module Kit
    class Xml
      include ActiveModel::Validations

      attr_reader :raw_xml, :document

      validate :validate_signature
      validate :validate_certificate

      def initialize(raw_xml)
        @raw_xml = raw_xml
        @document = Nokogiri::XML(raw_xml, nil, nil, Nokogiri::XML::ParseOptions::STRICT) do |config|
          config.noblanks
        end
      end

      def x509_certificates
        xpath = "//ds:KeyInfo/ds:X509Data/ds:X509Certificate"
        document.search(xpath, Xmldsig::NAMESPACES).map do |item|
          OpenSSL::X509::Certificate.new(Base64.decode64(item.text))
        end
      end

      private

      def validate_signature
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

      def validate_certificate(now = Time.current)
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
    end
  end
end
