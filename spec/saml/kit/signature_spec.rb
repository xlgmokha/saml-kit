# frozen_string_literal: true

RSpec.describe Saml::Kit::Signature do
  subject { described_class.new(signed_document.at_xpath('//ds:Signature')) }

  let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :signing) }
  let(:signed_document) do
    Saml::Kit::AuthenticationRequest.build do |x|
      x.sign_with(key_pair)
    end
  end
  let(:xml_hash) { Hash.from_xml(subject.to_xml) }

  specify { expect(subject.digest_value).to eql(xml_hash['Signature']['SignedInfo']['Reference']['DigestValue']) }
  specify { expect(subject.digest_method).to eql(xml_hash['Signature']['SignedInfo']['Reference']['DigestMethod']['Algorithm']) }
  specify { expect(subject.signature_value).to eql(xml_hash['Signature']['SignatureValue']) }
  specify { expect(subject.signature_method).to eql(xml_hash['Signature']['SignedInfo']['SignatureMethod']['Algorithm']) }
  specify { expect(subject.canonicalization_method).to eql(xml_hash['Signature']['SignedInfo']['CanonicalizationMethod']['Algorithm']) }
  specify { expect(subject.transforms).to eql(xml_hash['Signature']['SignedInfo']['Reference']['Transforms']['Transform'].map { |x| x['Algorithm'] }) }
  specify do
    expected = ::Xml::Kit::Certificate.new(xml_hash['Signature']['KeyInfo']['X509Data']['X509Certificate'], use: :signing)
    expect(subject.certificate).to eql(expected)
  end

  describe '#valid?' do
    it 'returns true when the signature is valid' do
      expect(subject).to be_valid
    end

    it 'is invalid when the xml has been tampered' do
      signed_document.at_xpath('//saml:Issuer').content = 'INVALID'
      expect(subject).not_to be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'is invalid when the signature is missing' do
      subject = described_class.new(nil)
      expect(subject).not_to be_valid
      expect(subject.errors[:base]).to match_array(['is missing.'])
    end

    it 'is invalid when the schema of the signature is invalid' do
      signature_element = signed_document.at_xpath('//ds:Signature')
      element = signature_element.at_xpath('./ds:SignedInfo', ds: Xml::Kit::Namespaces::XMLDSIG)
      element.name = 'BLAH'
      subject = described_class.new(signature_element)
      expect(subject).not_to be_valid
      expect(subject.errors[:base]).to include("1:0: ERROR: Element '{http://www.w3.org/2000/09/xmldsig#}BLAH': This element is not expected. Expected is ( {http://www.w3.org/2000/09/xmldsig#}SignedInfo ).")
    end

    describe 'certificate validation' do
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

      context 'when the certificate is expired' do
        let(:not_before) { 10.minutes.ago }
        let(:not_after) { 1.minute.ago }

        it 'is invalid' do
          expect(subject).to be_invalid
          expect(subject.errors[:certificate]).to match_array([
            "Not valid before #{expired_certificate.not_before}. Not valid after #{expired_certificate.not_after}."
          ])
        end
      end

      context 'when the certificate is not active yet' do
        let(:not_before) { 10.minutes.from_now }
        let(:not_after) { 20.minute.from_now }

        it 'invalid' do
          expect(subject).to be_invalid
          expect(subject.errors[:certificate]).to match_array([
            "Not valid before #{expired_certificate.not_before}. Not valid after #{expired_certificate.not_after}."
          ])
        end
      end
    end
  end

  describe '#to_h' do
    it 'returns a hash representation of the signature' do
      expected = Hash.from_xml(signed_document.to_s)['AuthnRequest']['Signature']
      expect(subject.to_h).to eql(expected)
    end
  end

  describe '#present?' do
    context 'when a signature is not present' do
      it 'return false' do
        expect(described_class.new(nil)).not_to be_present
      end
    end

    context 'when a signature is present' do
      it 'returns true' do
        expect(subject.present?).to be(true)
      end
    end
  end

  describe '#expected_digest_value' do
    it 'returns the expected digest value' do
      expected_digest = subject.digest_value

      signed_document.at_xpath('//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue').content = 'INVALID'
      subject = described_class.new(signed_document.at_xpath('//ds:Signature'))

      expect(subject.expected_digest_value).to eql(expected_digest)
    end
  end
end
