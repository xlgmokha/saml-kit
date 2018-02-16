RSpec.describe Saml::Kit::Signature do
  let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }
  let(:signed_document) do
    Saml::Kit::AuthenticationRequest.build do |x|
      x.sign_with(key_pair)
    end
  end
  subject { described_class.new(signed_document.at_xpath('//ds:Signature')) }

  describe "#valid?" do
    it 'returns true when the signature is valid' do
      expect(subject).to be_valid
    end

    it 'is invalid when the xml has been tampered' do
      signed_document.at_xpath('//saml:Issuer').content = "INVALID"
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'is invalid when the signature is missing' do
      subject = described_class.new(nil)
      expect(subject).to_not be_valid
      expect(subject.errors[:base]).to match_array(['is missing.'])
    end

    describe "certificate validation" do
      let(:key_pair) { ::Xml::Kit::KeyPair.new(expired_certificate, private_key, nil, :signing) }
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:expired_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.not_before = not_before
        certificate.not_after = not_after
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
        certificate
      end

      context "when the certificate is expired" do
        let(:not_before) { 10.minutes.ago }
        let(:not_after) { 1.minute.ago }

        it 'is invalid' do
          expect(subject).to be_invalid
          expect(subject.errors[:certificate]).to match_array([
            "Not valid before #{expired_certificate.not_before}. Not valid after #{expired_certificate.not_after}."
          ])
        end
      end

      context "when the certificate is not active yet" do
        let(:not_before) { 10.minutes.from_now }
        let(:not_after) { 20.minute.from_now }

        it 'it invalid' do
          expect(subject).to be_invalid
          expect(subject.errors[:certificate]).to match_array([
            "Not valid before #{expired_certificate.not_before}. Not valid after #{expired_certificate.not_after}."
          ])
        end
      end
    end
  end

  describe "#to_h" do
    it 'returns a hash representation of the signature' do
      expected = Hash.from_xml(signed_document.to_s)['AuthnRequest']['Signature']
      expect(subject.to_h).to eql(expected)
    end
  end

  describe "#present?" do
    context "when a signature is not present" do
      it 'return false' do
        expect(described_class.new(nil)).to_not be_present
      end
    end

    context "when a signature is present" do
      it 'returns true' do
        expect(subject).to be_present
      end
    end
  end
end
