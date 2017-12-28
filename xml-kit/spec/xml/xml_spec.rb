RSpec.describe Xml::Kit::Xml do
  class Item
    include ::Xml::Kit::Templatable

    attr_reader :id, :configuration

    def initialize(configuration)
      @id = ::Xml::Kit::Id.generate
      @configuration = configuration
    end

    def template_path
      current_path = File.expand_path(File.dirname(__FILE__))
      File.join(current_path, "../fixtures/item.builder")
    end
  end

  describe "#valid_signature?" do
    let(:login_url) { "https://#{FFaker::Internet.domain_name}/login" }
    let(:logout_url) { "https://#{FFaker::Internet.domain_name}/logout" }
    let(:configuration) do
      double(
        :configuration,
        sign?: true,
        key_pairs: [::Xml::Kit::KeyPair.generate(use: :signing)],
        signature_method: :SHA256,
        digest_method: :SHA256,
      )
    end
    let(:signed_xml) { Item.new(configuration).to_xml }

    it 'returns true, when the digest and signature is valid' do
      subject = described_class.new(signed_xml)
      expect(subject).to be_valid
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
