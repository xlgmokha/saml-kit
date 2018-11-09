# frozen_string_literal: true

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

    let(:active_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.not_before = 1.minute.ago
      certificate.not_after = 1.minute.from_now
      certificate.public_key = private_key.public_key
      certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
      certificate
    end
    let(:expired_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.not_before = 2.minutes.ago
      certificate.not_after = 1.minute.ago
      certificate.public_key = private_key.public_key
      certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
      certificate
    end
    let(:unsigned_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.not_before = 1.minute.ago
      certificate.not_after = 1.minute.from_now
      certificate.public_key = private_key.public_key
      certificate
    end
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    context 'when the use is not known' do
      specify { expect { subject.add_key_pair(active_certificate, private_key.export, use: :blah) }.to raise_error(/:signing or :encryption/) }
    end

    context 'when adding a signing key pair' do
      before do
        subject.add_key_pair(active_certificate.to_pem, private_key.export, use: :signing)
        subject.add_key_pair(expired_certificate.to_pem, private_key.export, use: :signing)
        subject.add_key_pair(unsigned_certificate.to_pem, private_key.export, use: :signing)
      end

      specify do
        expect(subject.key_pairs(use: :signing).map(&:certificate).map(&:fingerprint).map(&:to_s)).to match_array([
          Xml::Kit::Fingerprint.new(active_certificate.to_pem).to_s
        ])
      end
    end

    context 'when adding an encryption key pair' do
      before do
        subject.add_key_pair(active_certificate.to_pem, private_key.export, use: :encryption)
        subject.add_key_pair(expired_certificate.to_pem, private_key.export, use: :encryption)
        subject.add_key_pair(unsigned_certificate.to_pem, private_key.export, use: :encryption)
      end

      specify do
        expect(subject.key_pairs(use: :encryption).map(&:certificate).map(&:fingerprint).map(&:to_s)).to match_array([
          Xml::Kit::Fingerprint.new(active_certificate.to_pem).to_s
        ])
      end
    end
  end

  describe '#key_pairs' do
    context 'when a certificate expires' do
      let(:active_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.not_before = 1.minute.ago
        certificate.not_after = 1.minute.from_now
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
        certificate
      end
      let(:expired_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.not_before = 2.hours.ago
        certificate.not_after = 1.hour.ago
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
        certificate
      end
      let(:unsigned_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.not_before = 1.minute.ago
        certificate.not_after = 1.minute.from_now
        certificate.public_key = private_key.public_key
        certificate
      end
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

      before do
        subject.add_key_pair(active_certificate.to_pem, private_key.export, use: :signing)
        subject.add_key_pair(expired_certificate.to_pem, private_key.export, use: :signing)
        subject.add_key_pair(unsigned_certificate.to_pem, private_key.export, use: :signing)
      end

      specify { expect(subject.key_pairs.count).to be(1) }
      specify { expect(subject.key_pairs.map(&:certificate).map(&:fingerprint).map(&:to_s)).to match_array([Xml::Kit::Fingerprint.new(active_certificate).to_s]) }
    end

    context 'when there is more than one key pair' do
      let(:oldest_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.not_before = 45.minutes.ago
        certificate.not_after = 15.minutes.from_now
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
        certificate
      end
      let(:newest_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.not_before = 30.minutes.ago
        certificate.not_after = 30.minutes.from_now
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
        certificate
      end
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:fingerprints) { subject.key_pairs.map(&:certificate).map(&:fingerprint).map(&:to_s) }

      before do
        subject.add_key_pair(oldest_certificate.to_pem, private_key.export, use: :signing)
        subject.add_key_pair(newest_certificate.to_pem, private_key.export, use: :signing)
      end

      specify { expect(fingerprints[0]).to eql(Xml::Kit::Fingerprint.new(newest_certificate).to_s) }
      specify { expect(fingerprints[1]).to eql(Xml::Kit::Fingerprint.new(oldest_certificate).to_s) }
    end
  end
end
