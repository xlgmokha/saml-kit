RSpec.describe Saml::Kit::Signature do
  describe "#valid?" do
    let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }

    it 'returns true when the signature is valid' do
      signed_document = Saml::Kit::AuthenticationRequest.build do |x|
        x.sign_with(key_pair)
      end
      subject = described_class.new(Hash.from_xml(signed_document.to_xml))
      expect(subject).to be_valid
    end

    xit 'is invalid when the xml has been tampered' do
      signed_document = Saml::Kit::AuthenticationRequest.build do |x|
        x.sign_with(key_pair)
      end
      tampered_xml = signed_document.to_xml.gsub("Issuer", "Hacked")
      subject = described_class.new(Hash.from_xml(tampered_xml))
      expect(subject).to_not be_valid
    end
  end
end
