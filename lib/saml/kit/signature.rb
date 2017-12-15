module Saml
  module Kit
    class Signature
      def initialize(xml_hash, configuration:)
        @xml_hash = xml_hash
        @configuration = configuration
      end

      def certificate
        value = to_h.fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
        return if value.nil?
        Saml::Kit::Certificate.new(value, use: :signing)
      end

      def trusted?(metadata)
        return false if metadata.nil?
        metadata.matches?(certificate.fingerprint, use: :signing)
      end

      def to_h
        @xml_hash
      end
    end
  end
end
