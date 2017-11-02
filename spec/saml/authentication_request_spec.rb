require 'spec_helper'

RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml) }
  let(:id) { SecureRandom.uuid }
  let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:raw_xml) do
    builder = described_class::Builder.new
    builder.id = id
    builder.issued_at = Time.now.utc
    builder.issuer = issuer
    builder.acs_url = acs_url
    builder.to_xml
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql("_#{id}") }
  it { expect(subject.acs_url).to eql(acs_url) }

<<-EXAMPLE
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
  Version="2.0"
  IssueInstant="2014-07-16T23:52:45Z"
  AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
</samlp:AuthnRequest>
EXAMPLE
  describe "#to_xml" do
    subject { described_class::Builder.new(configuration) }
    let(:configuration) do
      config = Saml::Kit::Configuration.new
      config.issuer = issuer
      config
    end
    let(:issuer) { FFaker::Movie.title }
    let(:acs_url) { "https://airport.dev/session/acs" }

    it 'returns a valid authentication request' do
      travel_to DateTime.new(2014, 7, 16, 23, 52, 45)
      subject.acs_url = acs_url
      result = Hash.from_xml(subject.to_xml)

      expect(result['AuthnRequest']['ID']).to be_present
      expect(result['AuthnRequest']['Version']).to eql('2.0')
      expect(result['AuthnRequest']['IssueInstant']).to eql('2014-07-16T23:52:45Z')
      expect(result['AuthnRequest']['AssertionConsumerServiceURL']).to eql(acs_url)
      expect(result['AuthnRequest']['Issuer']).to eql(issuer)
      expect(result['AuthnRequest']['NameIDPolicy']['Format']).to eql("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    end
  end
end
