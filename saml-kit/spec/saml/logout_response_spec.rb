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

  describe "#serialize" do
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: { }) }
    let(:request) { double(id: SecureRandom.uuid, acs_url: acs_url, issuer: issuer, name_id_format: Saml::Kit::Namespaces::PERSISTENT, provider: nil) }
    let(:acs_url) { FFaker::Internet.http_url }
    let(:issuer) { FFaker::Internet.http_url }
    let(:builder) { described_class::Builder.new(user, request) }
    subject { builder.build }

    it 'returns a compressed and base64 encoded document' do
      expected_value = Base64.encode64(Zlib::Deflate.deflate(subject.to_xml, 9)).gsub(/\n/, '')
      expect(subject.serialize).to eql(expected_value)
    end
  end
end
