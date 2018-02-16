RSpec.describe Saml::Kit::Configuration do
  describe '#generate_key_pair_for' do
    subject { described_class.new }

    it 'raises an error when the use is not known' do
      expect do
        subject.generate_key_pair_for(use: :blah)
      end.to raise_error(/:signing or :encryption/)
    end

    it 'generates a signing key pair' do
      subject.generate_key_pair_for(use: :signing)
      expect(subject.key_pairs(use: :signing).count).to be(1)
    end

    it 'generates an encryption key pair' do
      subject.generate_key_pair_for(use: :encryption)
      expect(subject.key_pairs(use: :encryption).count).to be(1)
    end
  end

  describe '#add_key_pair' do
    subject { described_class.new }

    let(:certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.public_key = private_key.public_key
      certificate
    end
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    it 'raises an error when the use is not known' do
      expect do
        subject.add_key_pair(certificate, private_key.export, use: :blah)
      end.to raise_error(/:signing or :encryption/)
    end

    it 'adds a signing key pair' do
      subject.add_key_pair(certificate.to_pem, private_key.export, use: :signing)
      expect(subject.key_pairs(use: :signing).count).to be(1)
    end

    it 'adds an encryption key pair' do
      subject.add_key_pair(certificate.to_pem, private_key.export, use: :encryption)
      expect(subject.key_pairs(use: :encryption).count).to be(1)
    end
  end
end
