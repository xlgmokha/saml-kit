require 'rails_helper'

describe AuthenticationRequest do
  subject { described_class.new(raw_xml, registry) }
  let(:registry) { double }
  let(:id) { SecureRandom.uuid }
  let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:raw_xml) do
    builder = AuthenticationRequest::Builder.new
    builder.id = id
    builder.issued_at = Time.now.utc
    builder.issuer = issuer
    builder.acs_url = acs_url
    builder.to_xml
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql(id) }
  it { expect(subject.acs_url).to eql(acs_url) }

  describe "#valid?" do
    it 'returns false when the service provider is not known' do
      allow(registry).to receive(:registered?).with(issuer).and_return(false)
      expect(subject).to_not be_valid
    end

    it 'returns true when the service provider is registered' do
      allow(registry).to receive(:registered?).with(issuer).and_return(true)
      expect(subject).to be_valid
    end
  end
end
