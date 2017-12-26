RSpec.describe Xml::Kit::Fingerprint do
  describe "#sha" do
    it 'returns the SHA256' do
      certificate, _ = generate_key_pair("password")
      x509 = OpenSSL::X509::Certificate.new(certificate)
      sha256 = OpenSSL::Digest::SHA256.new.hexdigest(x509.to_der).upcase.scan(/../).join(":")

      expect(described_class.new(certificate).algorithm(OpenSSL::Digest::SHA256)).to eql(sha256)
    end

    it 'returns the SHA1' do
      certificate, _ = generate_key_pair("password")
      x509 = OpenSSL::X509::Certificate.new(certificate)
      sha1 = OpenSSL::Digest::SHA1.new.hexdigest(x509.to_der).upcase.scan(/../).join(":")

      expect(described_class.new(certificate).algorithm(OpenSSL::Digest::SHA1)).to eql(sha1)
    end
  end

  it 'produces correct hash keys' do
    certificate, _ = generate_key_pair("password")
    items = { }
    items[described_class.new(certificate)] = "HI"
    items[described_class.new(certificate)] = "BYE"
    expect(items.keys.count).to eql(1)
  end
end
