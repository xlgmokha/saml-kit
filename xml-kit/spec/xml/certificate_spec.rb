RSpec.describe Xml::Kit::Certificate do
  subject { described_class.new(certificate, use: :signing) }
  let(:certificate) do
    cert, _ = generate_key_pair('password')
    cert
  end

  describe "#fingerprint" do
    it 'returns a fingerprint' do
      expect(subject.fingerprint).to be_instance_of(Xml::Kit::Fingerprint)
    end
  end
end
