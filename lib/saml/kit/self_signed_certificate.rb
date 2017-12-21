module Saml
  module Kit
    class SelfSignedCertificate
      SUBJECT="/C=CA/ST=Alberta/L=Calgary/O=SamlKit/OU=SamlKit/CN=SamlKit"

      def initialize(passphrase)
        @passphrase = passphrase
      end

      def create
        rsa_key = OpenSSL::PKey::RSA.new(2048)
        public_key = rsa_key.public_key
        certificate = OpenSSL::X509::Certificate.new
        certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse(SUBJECT)
        certificate.not_before = DateTime.now.beginning_of_day
        certificate.not_after = 30.days.from_now
        certificate.public_key = public_key
        certificate.serial = 0x0
        certificate.version = 2
        certificate.sign(rsa_key, OpenSSL::Digest::SHA256.new)
        [
          certificate.to_pem,
          rsa_key.to_pem(OpenSSL::Cipher.new('AES-256-CBC'), @passphrase)
        ]
      end
    end
  end
end
