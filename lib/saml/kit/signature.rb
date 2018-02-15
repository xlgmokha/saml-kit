module Saml
  module Kit
    class Signature
      include ActiveModel::Validations
      include Translatable

      validate :validate_signature
      validate :validate_certificate

      attr_reader :name

      def initialize(item)
        @name = "Signature"
        if item.is_a?(Hash)
          @xml_hash = item
        else
          @node = item
        end
      end

      # Returns the embedded X509 Certificate
      def certificate
        if @xml_hash
          value = to_h.fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
          return if value.nil?
          ::Xml::Kit::Certificate.new(value, use: :signing)
        else
          return if @node.nil?
          item = @node.at_xpath("//ds:KeyInfo/ds:X509Data/ds:X509Certificate", "ds": ::Xml::Kit::Namespaces::XMLDSIG)
          ::Xml::Kit::Certificate.new(item.text, use: :signing)
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
        return errors[:base].push(error_message(:empty)) if certificate.nil?

        signature = Xmldsig::Signature.new(@node, 'ID=$uri or @Id')
        unless signature.valid?(certificate.x509)
          signature.errors.each do |attribute|
            errors.add(attribute, error_message(attribute))
          end
        end
      end

      def validate_certificate(now = Time.now.utc)
        if certificate.present? && !certificate.active?(now)
          error_message = "Not valid before #{certificate.not_before}. Not valid after #{certificate.not_after}."
          errors.add(:certificate, error_message)
        end
      end
    end
  end
end
