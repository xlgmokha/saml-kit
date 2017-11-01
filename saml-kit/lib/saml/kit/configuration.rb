module Saml
  module Kit
    class Configuration
      BEGIN_CERT=/-----BEGIN CERTIFICATE-----/
      END_CERT=/-----END CERTIFICATE-----/

      attr_accessor :issuer, :acs_url
      attr_accessor :signature_method, :digest_method
      attr_accessor :signing_certificate_pem, :signing_private_key_pem, :signing_private_key_password

      def initialize
        @signature_method = :SHA256
        @digest_method = :SHA256
        @signing_certificate_pem, @signing_private_key_pem, @signing_private_key_password = create_self_signed_certificate
      end

      def stripped_signing_certificate
        signing_certificate_pem.to_s.gsub(BEGIN_CERT, '').gsub(END_CERT, '').gsub(/\n/, '')
      end

      def signing_private_key
        OpenSSL::PKey::RSA.new(signing_private_key_pem, signing_private_key_password)
      end

      private

      def create_self_signed_certificate
        rsa_key = OpenSSL::PKey::RSA.new(2048)
        public_key = rsa_key.public_key
        certificate = OpenSSL::X509::Certificate.new
        certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/C=CA/ST=Alberta/L=Calgary/O=Xsig/OU=Xsig/CN=Xsig")
        certificate.not_before = Time.now
        certificate.not_after = Time.now + 365 * 24 * 60 * 60
        certificate.public_key = public_key
        certificate.serial = 0x0
        certificate.version = 2
        factory = OpenSSL::X509::ExtensionFactory.new
        factory.subject_certificate = factory.issuer_certificate = certificate
        certificate.extensions = [ factory.create_extension("basicConstraints","CA:TRUE", true), factory.create_extension("subjectKeyIdentifier", "hash"), ]
        certificate.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))
        certificate.sign(rsa_key, OpenSSL::Digest::SHA256.new)

        password = SecureRandom.uuid
        [
          certificate.to_pem,
          rsa_key.to_pem(OpenSSL::Cipher::Cipher.new('des3'), password),
          password
        ]
      end
    end
  end
end
