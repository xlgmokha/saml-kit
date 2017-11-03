module Saml
  module Kit
    class Configuration
      BEGIN_CERT=/-----BEGIN CERTIFICATE-----/
      END_CERT=/-----END CERTIFICATE-----/

      attr_accessor :issuer
      attr_accessor :signature_method, :digest_method
      attr_accessor :signing_certificate_pem, :signing_private_key_pem, :signing_private_key_password
      attr_accessor :service_provider_registry

      def initialize
        #@issuer = SecureRandom.uuid
        @signature_method = :SHA256
        @digest_method = :SHA256
        @signing_private_key_password = SecureRandom.uuid
        @signing_certificate_pem, @signing_private_key_pem = SelfSignedCertificate.new(@signing_private_key_password).create
        @service_provider_registry = DefaultServiceProviderRegistry.new
      end

      def stripped_signing_certificate
        signing_certificate_pem.to_s.gsub(BEGIN_CERT, '').gsub(END_CERT, '').gsub(/\n/, '')
      end

      def signing_x509
        OpenSSL::X509::Certificate.new(signing_certificate_pem)
      end

      def signing_private_key
        OpenSSL::PKey::RSA.new(signing_private_key_pem, signing_private_key_password)
      end
    end
  end
end
