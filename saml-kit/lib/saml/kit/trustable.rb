module Saml
  module Kit
    module Trustable
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
    end
  end
end
