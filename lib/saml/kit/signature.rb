module Saml
  module Kit
    class Signature
      def initialize(xml_hash)
        @xml_hash = xml_hash
      end

      # Returns the embedded X509 Certificate
      def certificate
        value = to_h.fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
        return if value.nil?
        ::Xml::Kit::Certificate.new(value, use: :signing)
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
    end
  end
end
