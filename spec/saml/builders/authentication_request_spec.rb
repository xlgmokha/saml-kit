require 'spec_helper'

RSpec.describe Saml::Kit::Builders::AuthenticationRequest do
  subject { described_class.new(configuration: configuration) }
  let(:configuration) do
    config = Saml::Kit::Configuration.new
    config.issuer = issuer
    config
  end

  describe "#to_xml" do
    let(:issuer) { FFaker::Movie.title }
    let(:assertion_consumer_service_url) { "https://airport.dev/session/acs" }

    it 'returns a valid authentication request' do
      travel_to 1.second.from_now
      subject.assertion_consumer_service_url = assertion_consumer_service_url
      result = Hash.from_xml(subject.to_xml)

      expect(result['AuthnRequest']['ID']).to be_present
      expect(result['AuthnRequest']['Version']).to eql('2.0')
      expect(result['AuthnRequest']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(result['AuthnRequest']['AssertionConsumerServiceURL']).to eql(assertion_consumer_service_url)
      expect(result['AuthnRequest']['Issuer']).to eql(issuer)
      expect(result['AuthnRequest']['NameIDPolicy']['Format']).to eql(Saml::Kit::Namespaces::PERSISTENT)
    end

    it 'marks acs_url as deprecated' do
      subject.acs_url = FFaker::Internet.uri('https')
      expect(subject.assertion_consumer_service_url).to eql(subject.acs_url)
    end
  end
end
