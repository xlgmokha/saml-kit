RSpec.describe Xml::Kit::Document do
  class Item
    include ::Xml::Kit::Templatable

    attr_reader :id, :signing_key_pair

    def initialize
      @id = ::Xml::Kit::Id.generate
      @signing_key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
      @embed_signature = true
    end

    def template_path
      current_path = File.expand_path(File.dirname(__FILE__))
      File.join(current_path, "../fixtures/item.builder")
    end
  end

  describe "#valid_signature?" do
    let(:login_url) { "https://#{FFaker::Internet.domain_name}/login" }
    let(:logout_url) { "https://#{FFaker::Internet.domain_name}/logout" }
    let(:signed_xml) { Item.new.to_xml }

    it 'returns true, when the digest and signature is valid' do
      expect(described_class.new(signed_xml)).to be_valid
    end

    it 'returns false, when the SHA1 digest is not valid' do
      subject = described_class.new(signed_xml.gsub("Item", "uhoh"))
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'it is invalid when digest is incorrect' do
      old_digest = Hash.from_xml(signed_xml)['Item']['Signature']['SignedInfo']['Reference']['DigestValue']

      subject = described_class.new(signed_xml.gsub(old_digest, 'sabotage'))
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'returns false, when the signature is invalid' do
      old_signature = Hash.from_xml(signed_xml)['Item']['Signature']['SignatureValue']
      signed_xml.gsub!(old_signature, 'sabotage')
      subject = described_class.new(signed_xml)
      expect(subject).to_not be_valid
      expect(subject.errors[:signature]).to be_present
    end
  end
end
