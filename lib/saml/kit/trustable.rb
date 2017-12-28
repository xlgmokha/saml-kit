module Saml
  module Kit
    module Trustable
      extend ActiveSupport::Concern

      included do
        validate :must_have_valid_signature, unless: :signature_manually_verified
        validate :must_be_registered
        validate :must_be_trusted
      end

      # Returns true when the document has an embedded XML Signature or has been verified externally.
      def signed?
        signature_manually_verified || signature.present?
      end

      # @!visibility private
      def signature
        xml_hash = to_h.fetch(name, {}).fetch('Signature', nil)
        xml_hash ? Signature.new(xml_hash) : nil
      end

      # Returns true when documents is signed and the signing certificate belongs to a known service entity.
      def trusted?
        return true if signature_manually_verified
        return false unless signed?
        signature.trusted?(provider)
      end

      # @!visibility private
      def provider
        configuration.registry.metadata_for(issuer)
      end

      # @!visibility private
      def signature_verified!
        @signature_manually_verified = true
      end

      private

      attr_reader :signature_manually_verified

      def must_have_valid_signature
        return if to_xml.blank?

        xml = ::Xml::Kit::Document.new(to_xml, namespaces: {
          "NameFormat": Namespaces::ATTR_SPLAT,
          "ds": ::Xml::Kit::Namespaces::XMLDSIG,
          "md": Namespaces::METADATA,
          "saml": Namespaces::ASSERTION,
          "samlp": Namespaces::PROTOCOL,
        })
        xml.valid?
        xml.errors.each do |error|
          errors[:base] << error
        end
      end

      def must_be_registered
        return unless expected_type?
        return if provider.present?
        errors[:provider] << error_message(:unregistered)
      end

      def must_be_trusted
        return if trusted?
        return if provider.present? && !signed?
        errors[:fingerprint] << error_message(:invalid_fingerprint)
      end
    end
  end
end
