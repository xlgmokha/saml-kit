RSpec.describe Saml::Kit::Builders::LogoutResponse do
  subject { described_class.new(request) }

  let(:user) { double(:user, name_id_for: SecureRandom.uuid) }
  let(:request) { Saml::Kit::Builders::LogoutRequest.new(user).build }
  let(:issuer) { FFaker::Internet.http_url }
  let(:destination) { FFaker::Internet.http_url }

  describe '#build' do
    it 'builds a logout response' do
      travel_to 1.second.from_now

      subject.issuer = issuer
      subject.destination = destination
      result = subject.build
      expect(result.id).to be_present
      expect(result.issue_instant).to eql(Time.now.utc)
      expect(result.version).to eql('2.0')
      expect(result.issuer).to eql(issuer)
      expect(result.status_code).to eql(Saml::Kit::Namespaces::SUCCESS)
      expect(result.in_response_to).to eql(request.id)
      expect(result.destination).to eql(destination)
    end
  end
end
