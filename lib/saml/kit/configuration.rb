module Saml
  module Kit
    class Configuration
      attr_accessor :issuer
      attr_accessor :signature_method, :digest_method
      attr_accessor :registry, :session_timeout
      attr_accessor :logger

      def initialize
        @signature_method = :SHA256
        @digest_method = :SHA256
        @registry = DefaultRegistry.new
        @session_timeout = 3.hours
        @logger = Logger.new(STDOUT)
        yield self if block_given?
      end

      def add_key_pair(certificate, private_key, password:, use: :signing)
        key_pairs.push({
          certificate: Saml::Kit::Certificate.new(certificate, use: use),
          private_key: OpenSSL::PKey::RSA.new(private_key, password)
        })
      end

      def generate_key_pair_for(use:, password: SecureRandom.uuid)
        certificate, private_key = SelfSignedCertificate.new(password).create
        add_key_pair(certificate, private_key, password: password, use: use)
      end

      def certificates(use: nil)
        certificates = key_pairs.map { |x| x[:certificate] }
        use.present? ? certificates.find_all { |x| x.for?(use) } : certificates
      end

      def private_keys(use: :signing)
        key_pairs.find_all { |x| x[:certificate].for?(use) }.map { |x| x[:private_key] }
      end

      def encryption_certificate
        Saml::Kit.deprecate("encryption_certificate is deprecated. Use certificates(use: :encryption) instead")
        certificates(use: :encryption).last
      end

      def signing_private_key
        Saml::Kit.deprecate("signing_private_key is deprecated. Use private_keys(use: :signing) instead")
        private_keys(use: :signing).last
      end

      def encryption_private_key
        Saml::Kit.deprecate("encryption_private_key is deprecated. Use private_keys(use: :encryption) instead")
        private_keys(use: :encryption).last
      end

      def sign?
        certificates(use: :signing).any?
      end

      private

      def key_pairs
        @key_pairs ||= []
      end
    end
  end
end
