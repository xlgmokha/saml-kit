require 'spec_helper'

RSpec.describe Saml::Kit::LogoutResponse do
  describe described_class::Builder do
    subject { described_class.new(user, request, configuration: configuration) }
    let(:configuration) { double(issuer: issuer)  }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid) }
    let(:request) { Saml::Kit::LogoutRequest::Builder.new(user).build }
    let(:issuer) { FFaker::Internet.http_url }

    describe "#build" do
      it 'builds a logout response' do
        travel_to 1.second.from_now

        result = subject.build
        expect(result.id).to be_present
        expect(result.issue_instant).to eql(Time.now.utc.iso8601)
        expect(result.version).to eql("2.0")
        expect(result.issuer).to eql(issuer)
        expect(result.status_code).to eql(Saml::Kit::Namespaces::SUCCESS)
        expect(result.in_response_to).to eql(request.id)
        expect(result.destination).to be_present
      end
    end
  end
end
