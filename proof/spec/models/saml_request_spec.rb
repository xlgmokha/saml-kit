require 'rails_helper'

describe AuthenticationRequest do
  subject { described_class.new(raw_xml, registry) }
  let(:registry) { double }
  let(:acs_url) { "https://blah.dev/acs" }

  describe "#valid?" do
    let(:raw_xml) do
      builder = AuthenticationRequest::Builder.new
      builder.id = SecureRandom.uuid
      builder.issued_at = Time.now.utc
      builder.issuer = "my-issuer"
      builder.acs_url = acs_url
      builder.to_xml
    end

    it 'returns false when the service provider is not known' do
      allow(registry).to receive(:registered?).with("my-issuer").and_return(false)
      expect(subject).to_not be_valid
    end

    it 'returns true when the service provider is registered' do
      allow(registry).to receive(:registered?).with("my-issuer").and_return(true)
      expect(subject).to be_valid
    end
  end
end
