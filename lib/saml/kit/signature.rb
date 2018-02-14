module Saml
  module Kit
    class Signature
      include ActiveModel::Validations

      validate :validate_signature
      validate :validate_certificate

      def initialize(xml_hash)
        if xml_hash.is_a?(Hash)
          @xml_hash = xml_hash
        else
          @document = xml_hash
        end
      end

      # Returns the embedded X509 Certificate
      def certificate
        if @document
          item = @document.at_xpath("//ds:KeyInfo/ds:X509Data/ds:X509Certificate", "ds": ::Xml::Kit::Namespaces::XMLDSIG)
          ::Xml::Kit::Certificate.new(item.text, use: :signing)
        else
          value = to_h.fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
          return if value.nil?
          ::Xml::Kit::Certificate.new(value, use: :signing)
        end
      end

      # Returns true when the fingerprint of the certificate matches one of the certificates registered in the metadata.
      def trusted?(metadata)
        return false if metadata.nil?
        metadata.matches?(certificate.fingerprint, use: :signing)
      end

      # Returns the XML Hash.
      def to_h
        @xml_hash
      end

      private

      def validate_signature
        return errors[:base].push("is missing") if certificate.nil?

        signature = Xmldsig::Signature.new(@document, 'ID=$uri or @Id')
        unless signature.valid?(certificate.x509)
          signature.errors.each { |error| errors.add(error, "is invalid") }
        end
      end

      def validate_certificate(now = Time.current)
        if certificate.present? && certificate.expired?(now)
          error_message = "Not valid before #{certificate.not_before}. Not valid after #{certificate.not_after}."
          errors.add(:certificate, error_message)
        end
      end
    end
  end
end
