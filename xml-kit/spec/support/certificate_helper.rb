module CertificateHelper
  def generate_key_pair(passphrase)
    ::Xml::Kit::SelfSignedCertificate.new(passphrase).create
  end
end
