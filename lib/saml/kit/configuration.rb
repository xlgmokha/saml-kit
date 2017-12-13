module Saml
  module Kit
    class Configuration
      attr_accessor :issuer
      attr_accessor :signature_method, :digest_method
      attr_accessor :encryption_certificate_pem, :encryption_private_key_pem, :encryption_private_key_password
      attr_accessor :registry, :session_timeout
      attr_accessor :logger

      def initialize
        @signature_method = :SHA256
        @digest_method = :SHA256
        signing_private_key_password = SecureRandom.uuid
        @encryption_private_key_password = SecureRandom.uuid
        signing_certificate_pem, signing_private_key_pem = SelfSignedCertificate.new(signing_private_key_password).create
        add_key_pair(signing_certificate_pem, signing_private_key_pem, password: signing_private_key_password, use: :signing)
        @encryption_certificate_pem, @encryption_private_key_pem = SelfSignedCertificate.new(@encryption_private_key_password).create
        @registry = DefaultRegistry.new
        @session_timeout = 3.hours
        @logger = Logger.new(STDOUT)
      end

      def add_key_pair(certificate, private_key, password:, use: :signing)
        key_pairs.push({
          certificate: Saml::Kit::Certificate.new(certificate, use: use),
          private_key: OpenSSL::PKey::RSA.new(private_key, password)
        })
      end

      def certificates(use: :signing)
        key_pairs.map { |x| x[:certificate] }.find_all { |x| x.for?(use) }
      end

      def private_keys(use: :signing)
        key_pairs.find_all { |x| x[:certificate].for?(use) }.map { |x| x[:private_key] }
      end

      def signing_certificate
        certificates(use: :signing).last
      end

      def encryption_certificate
        Saml::Kit::Certificate.new(encryption_certificate_pem, use: :encryption)
      end

      def signing_private_key
        private_keys(use: :signing).last
      end

      def encryption_private_key
        OpenSSL::PKey::RSA.new(encryption_private_key_pem, encryption_private_key_password)
      end

      private

      def key_pairs
        @key_pairs ||= []
      end
    end
  end
end
