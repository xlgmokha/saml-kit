RSpec.describe Saml::Kit::Signature do
  describe "#valid?" do
    let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }
    let(:signed_document) do
      Saml::Kit::AuthenticationRequest.build do |x|
        x.sign_with(key_pair)
      end
    end
    subject { described_class.new(signed_document.at_xpath('//ds:Signature')) }

    it 'returns true when the signature is valid' do
      expect(subject).to be_valid
    end

    it 'is invalid when the xml has been tampered' do
      signed_document.at_xpath('//saml:Issuer').content = "INVALID"
      expect(subject).to_not be_valid
    end

    it 'is invalid when the signature is missing' do
      unsigned_document = Saml::Kit::AuthenticationRequest.build
      subject = described_class.new(Hash.from_xml(unsigned_document.to_xml))
      expect(subject).to_not be_valid
      expect(subject.errors[:base]).to be_present
    end
  end
end
