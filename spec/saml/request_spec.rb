require 'spec_helper'

RSpec.describe Saml::Kit::Request do
  describe ".encode" do
    subject { described_class }

    it 'returns a compressed and base64 encoded document' do
      xml = "<xml></xml>"
      document = double(to_xml: xml)

      expected_value = Base64.encode64(Zlib::Deflate.deflate(xml, 9)).gsub(/\n/, '')
      expect(subject.encode(document)).to eql(expected_value)
    end
  end

  describe ".decode" do
    subject { described_class }
    let(:issuer) { FFaker::Internet.http_url }

    it 'decodes the raw_request' do
      builder = Saml::Kit::AuthenticationRequest::Builder.new
      builder.issuer = issuer
      raw_saml = subject.encode(builder)

      result = subject.decode(raw_saml)
      expect(result.issuer).to eql(issuer)
    end
  end
end
