require 'spec_helper'

RSpec.describe Saml::Kit::LogoutResponse do
  describe described_class::Builder do
    subject { described_class.new(user, request, configuration: configuration) }
    let(:configuration) { double(issuer: issuer)  }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid) }
    let(:request) { Saml::Kit::LogoutRequest::Builder.new(user).build }
    let(:issuer) { FFaker::Internet.http_url }
    let(:destination) { FFaker::Internet.http_url }
    let(:registry) { double(:registry) }
    let(:provider) { double(:provider) }
    let(:binding) { double(:binding, location: destination) }

    describe "#build" do
      it 'builds a logout response' do
        allow(configuration).to receive(:registery).and_return(registry)
        allow(registry).to receive(:metadata_for).with(issuer).and_return(provider)
        allow(registry).to receive(:single_logout_service_for).and_return(binding)

        travel_to 1.second.from_now

        result = subject.build
        expect(result.id).to be_present
        expect(result.issue_instant).to eql(Time.now.utc.iso8601)
        expect(result.version).to eql("2.0")
        expect(result.issuer).to eql(issuer)
        expect(result.status_code).to eql(Saml::Kit::Namespaces::SUCCESS)
        expect(result.in_response_to).to eql(request.id)
        expect(result.destination).to eql(destination)
      end
    end
  end
end
