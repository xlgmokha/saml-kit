require 'spec_helper'

RSpec.describe Saml::Kit::Builders::Assertion do
  describe "#build" do
    let(:email) { FFaker::Internet.email }
    let(:assertion_consumer_service_url) { FFaker::Internet.uri('https') }
    let(:user) { User.new(attributes: { email: email, created_at: Time.now.utc.iso8601 }) }
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: Xml::Kit::Id.generate, assertion_consumer_service_url: assertion_consumer_service_url, issuer: issuer, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: provider, trusted?: true, signed?: true) }
    let(:provider) { instance_double(Saml::Kit::ServiceProviderMetadata, want_assertions_signed: false, encryption_certificates: [configuration.certificates(use: :encryption).last]) }
    let(:issuer) { FFaker::Internet.uri('https') }
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.entity_id = issuer
        config.generate_key_pair_for(use: :signing)
        config.generate_key_pair_for(use: :encryption)
      end
    end

    subject { described_class.new(user, request, configuration: configuration) }

    specify { expect(subject.build).to be_valid }
  end
end
