module Saml
  module Kit
    class KeyPair # :nodoc:
      attr_reader :certificate, :private_key, :use

      def initialize(certificate, private_key, passphrase, use)
        @use = use
        @certificate = Saml::Kit::Certificate.new(certificate, use: use)
        @private_key = OpenSSL::PKey::RSA.new(private_key, passphrase)
      end

      # Returns true if the key pair is the designated use.
      #
      # @param use [Symbol] Can be either `:signing` or `:encryption`.
      def for?(use)
        @use == use
      end

      # Returns a generated self signed certificate with private key.
      #
      # @param use [Symbol] Can be either `:signing` or `:encryption`.
      # @param passphrase [String] the passphrase to use to encrypt the private key.
      def self.generate(use:, passphrase: SecureRandom.uuid)
        certificate, private_key = SelfSignedCertificate.new(passphrase).create
        new(certificate, private_key, passphrase, use)
      end
    end
  end
end
