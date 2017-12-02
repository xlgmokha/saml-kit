require "spec_helper"

RSpec.describe Saml::Kit::Signature do
  let(:configuration) do
    config = Saml::Kit::Configuration.new
    config.signing_certificate_pem = certificate
    config.signing_private_key_pem = private_key
    config.signing_private_key_password = password
    config
  end

  let(:reference_id) { "_#{SecureRandom.uuid}" }
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { rsa_key.public_key }
  let(:certificate) do
    x = OpenSSL::X509::Certificate.new
    x.subject = x.issuer = OpenSSL::X509::Name.parse("/C=CA/ST=Alberta/L=Calgary/O=Xsig/OU=Xsig/CN=Xsig")
    x.not_before = Time.now
    x.not_after = Time.now + 365 * 24 * 60 * 60
    x.public_key = public_key
    x.serial = 0x0
    x.version = 2
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = factory.issuer_certificate = x
    x.extensions = [ factory.create_extension("basicConstraints","CA:TRUE", true), factory.create_extension("subjectKeyIdentifier", "hash"), ]
    x.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))
    x.sign(rsa_key, OpenSSL::Digest::SHA256.new)
    x.to_pem
  end
  let(:private_key) { rsa_key.to_pem(OpenSSL::Cipher::Cipher.new('des3'), password) }
  let(:password) { "password" }

  it 'generates a signature' do
    options = {
      "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
      "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
      ID: reference_id,
    }
    signed_xml = described_class.sign(sign: true, configuration: configuration) do |xml, signature|
      xml.tag!('samlp:AuthnRequest', options) do
        signature.template(reference_id)
        xml.tag!('saml:Issuer', "MyEntityID")
      end
    end
    result = Hash.from_xml(signed_xml)

    signature = result["AuthnRequest"]["Signature"]
    expect(signature['xmlns']).to eql("http://www.w3.org/2000/09/xmldsig#")
    expect(signature['SignedInfo']['CanonicalizationMethod']['Algorithm']).to eql('http://www.w3.org/2001/10/xml-exc-c14n#')
    expect(signature['SignedInfo']['SignatureMethod']['Algorithm']).to eql("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

    expect(signature['SignedInfo']['Reference']['URI']).to eql("##{reference_id}")
    expect(signature['SignedInfo']['Reference']['Transforms']['Transform']).to match_array([
      { "Algorithm" => "http://www.w3.org/2000/09/xmldsig#enveloped-signature" },
      { "Algorithm" => "http://www.w3.org/2001/10/xml-exc-c14n#" }
    ])
    expect(signature['SignedInfo']['Reference']['DigestMethod']['Algorithm']).to eql("http://www.w3.org/2001/04/xmlenc#sha256")
    expected_certificate = certificate.gsub(/\n/, '').gsub(/-----BEGIN CERTIFICATE-----/, '').gsub(/-----END CERTIFICATE-----/, '')
    expect(signature['KeyInfo']['X509Data']['X509Certificate']).to eql(expected_certificate)
    expect(signature['SignedInfo']['Reference']['DigestValue']).to be_present
    expect(signature['SignatureValue']).to be_present
    expect(OpenSSL::X509::Certificate.new(Base64.decode64(signature['KeyInfo']['X509Data']['X509Certificate']))).to be_present
  end

  it 'does not add a signature' do
    signed_xml = described_class.sign(sign: false, configuration: configuration) do |xml, signature|
      xml.AuthnRequest do
        signature.template(reference_id)
        xml.Issuer "MyEntityID"
      end
    end
    result = Hash.from_xml(signed_xml)
    expect(result['AuthnRequest']).to be_present
    expect(result["AuthnRequest"]["Signature"]).to be_nil
  end
end
