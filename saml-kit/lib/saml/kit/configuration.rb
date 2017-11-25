module Saml
  module Kit
    class Configuration
      BEGIN_CERT=/-----BEGIN CERTIFICATE-----/
      END_CERT=/-----END CERTIFICATE-----/

      attr_accessor :issuer
      attr_accessor :signature_method, :digest_method
      attr_accessor :signing_certificate_pem, :signing_private_key_pem, :signing_private_key_password
      attr_accessor :encryption_certificate_pem, :encryption_private_key_pem, :encryption_private_key_password
      attr_accessor :registry, :session_timeout
      attr_accessor :logger

      def initialize
        @signature_method = :SHA256
        @digest_method = :SHA256
        @signing_private_key_password = SecureRandom.uuid
        @encryption_private_key_password = SecureRandom.uuid
        @signing_certificate_pem, @signing_private_key_pem = SelfSignedCertificate.new(@signing_private_key_password).create
        @encryption_certificate_pem, @encryption_private_key_pem = SelfSignedCertificate.new(@encryption_private_key_password).create
        @registry = DefaultRegistry.new
        @session_timeout = 3.hours
        @logger = Logger.new(STDOUT)
      end

      def stripped_signing_certificate
        normalize(signing_certificate_pem)
      end

      def stripped_encryption_certificate
        normalize(encryption_certificate_pem)
      end

      def signing_x509
        OpenSSL::X509::Certificate.new(signing_certificate_pem)
      end

      def encryption_x509
        OpenSSL::X509::Certificate.new(encryption_certificate_pem)
      end

      def signing_private_key
        OpenSSL::PKey::RSA.new(signing_private_key_pem, signing_private_key_password)
      end

      def encryption_private_key
        OpenSSL::PKey::RSA.new(encryption_private_key_pem, encryption_private_key_password)
      end

      private

      def normalize(certificate)
        certificate.to_s.gsub(BEGIN_CERT, '').gsub(END_CERT, '').gsub(/\n/, '')
      end
    end
  end
end
