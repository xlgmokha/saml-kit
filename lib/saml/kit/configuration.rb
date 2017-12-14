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

      def generate_key_pair_for(use:)
        private_key_password = SecureRandom.uuid
        certificate_pem, private_key_pem = SelfSignedCertificate.new(private_key_password).create
        add_key_pair(certificate_pem, private_key_pem, password: private_key_password, use: use)
      end

      def certificates(use: nil)
        certificates = key_pairs.map { |x| x[:certificate] }
        use.present? ? certificates.find_all { |x| x.for?(use) } : certificates
      end

      def private_keys(use: :signing)
        key_pairs.find_all { |x| x[:certificate].for?(use) }.map { |x| x[:private_key] }
      end

      def encryption_certificate
        certificates(use: :encryption).last
      end

      def signing_private_key
        private_keys(use: :signing).last
      end

      def encryption_private_key
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
