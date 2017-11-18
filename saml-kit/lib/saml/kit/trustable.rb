module Saml
  module Kit
    module Trustable
      extend ActiveSupport::Concern

      included do
        validate :must_have_valid_signature
      end

      def certificate
        return unless signed?
        to_h.fetch(name, {}).fetch('Signature', {}).fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
      end

      def fingerprint
        return if certificate.blank?
        Fingerprint.new(certificate)
      end

      def signed?
        to_h[name]['Signature'].present?
      end

      def trusted?
        return false if provider.nil?
        return false unless signed?
        provider.matches?(fingerprint, use: :signing)
      end

      def provider
        registry.metadata_for(issuer)
      end

      def registry
        Saml::Kit.configuration.registry
      end

      private

      def must_have_valid_signature
        return if to_xml.blank?

        xml = Saml::Kit::Xml.new(to_xml)
        xml.valid?
        xml.errors.each do |error|
          errors[:base] << error
        end
      end
    end
  end
end
