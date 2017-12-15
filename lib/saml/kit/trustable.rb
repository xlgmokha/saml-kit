module Saml
  module Kit
    module Trustable
      extend ActiveSupport::Concern

      included do
        validate :must_have_valid_signature, unless: :signature_manually_verified
        validate :must_be_registered
        validate :must_be_trusted, unless: :signature_manually_verified
      end

      def signed?
        signature.present?
      end

      def signature
        xml_hash = to_h.fetch(name, {}).fetch('Signature', nil)
        xml_hash ? Signature.new(xml_hash, configuration: configuration) : nil
      end

      def trusted?
        return false unless signed?
        signature.trusted?(provider)
      end

      def provider
        configuration.registry.metadata_for(issuer)
      end

      def signature_verified!
        @signature_manually_verified = true
      end

      private

      attr_reader :signature_manually_verified

      def must_have_valid_signature
        return if to_xml.blank?

        xml = Saml::Kit::Xml.new(to_xml)
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
