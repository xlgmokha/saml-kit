module Saml
  module Kit
    class KeyPair # :nodoc:
      attr_reader :certificate, :private_key, :use

      def initialize(certificate, private_key, passphrase, use)
        @use = use
        @certificate = Saml::Kit::Certificate.new(certificate, use: use)
        @private_key = OpenSSL::PKey::RSA.new(private_key, passphrase)
      end

      def for?(use)
        @use == use
      end

      def self.generate(use:, passphrase: SecureRandom.uuid)
        certificate, private_key = SelfSignedCertificate.new(passphrase).create
        new(certificate, private_key, passphrase, use)
      end
    end
  end
end
