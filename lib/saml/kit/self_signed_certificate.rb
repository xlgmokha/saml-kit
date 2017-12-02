module Saml
  module Kit
    class SelfSignedCertificate
      def initialize(password)
        @password = password
      end

      def create
        rsa_key = OpenSSL::PKey::RSA.new(2048)
        public_key = rsa_key.public_key
        certificate = OpenSSL::X509::Certificate.new
        certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/C=CA/ST=Alberta/L=Calgary/O=SamlKit/OU=SamlKit/CN=SamlKit")
        certificate.not_before = DateTime.now.beginning_of_day
        certificate.not_after = 30.days.from_now
        certificate.public_key = public_key
        certificate.serial = 0x0
        certificate.version = 2
        factory = OpenSSL::X509::ExtensionFactory.new
        factory.subject_certificate = factory.issuer_certificate = certificate
        certificate.extensions = [ factory.create_extension("basicConstraints","CA:TRUE", true), factory.create_extension("subjectKeyIdentifier", "hash"), ]
        certificate.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))
        certificate.sign(rsa_key, OpenSSL::Digest::SHA256.new)
        [
          certificate.to_pem,
          rsa_key.to_pem(OpenSSL::Cipher.new('AES-256-CBC'), @password)
        ]
      end
    end
  end
end
