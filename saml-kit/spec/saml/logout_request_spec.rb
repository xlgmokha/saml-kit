require 'spec_helper'

RSpec.describe Saml::Kit::LogoutRequest do
  describe described_class::Builder do
    let(:logout_url) { FFaker::Internet.http_url }

    it 'includes a LogoutRequest element' do
      travel_to 1.second.from_now
      subject.destination = logout_url
      result = Hash.from_xml(subject.to_xml)

      expect(result['LogoutRequest']).to be_present
      expect(result['LogoutRequest']['ID']).to be_present
      expect(result['LogoutRequest']['Version']).to eql("2.0")
      expect(result['LogoutRequest']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(result['LogoutRequest']['Destination']).to eql(logout_url)
      expect(result['LogoutRequest']['xmlns']).to eql(Saml::Kit::Namespaces::PROTOCOL)
    end
  end
end
