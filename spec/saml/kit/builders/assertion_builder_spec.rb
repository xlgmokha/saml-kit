# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Saml::Kit::Builders::Assertion do
  describe '#build' do
    subject { described_class.new(user, authn_request, configuration: configuration) }

    let(:email) { FFaker::Internet.email }
    let(:assertion_consumer_service_url) { FFaker::Internet.uri('https') }
    let(:user) { User.new(attributes: { email: email, created_at: Time.now.utc.iso8601 }) }
    let(:authn_request) { instance_double(Saml::Kit::AuthenticationRequest, id: Xml::Kit::Id.generate, assertion_consumer_service_url: assertion_consumer_service_url, issuer: issuer, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: provider, trusted?: true, signed?: true) }
    let(:provider) { instance_double(Saml::Kit::ServiceProviderMetadata, want_assertions_signed: false, encryption_certificates: [configuration.certificates(use: :encryption).last]) }
    let(:issuer) { FFaker::Internet.uri('https') }
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.entity_id = issuer
        config.registry = registry
        config.generate_key_pair_for(use: :signing)
        config.generate_key_pair_for(use: :encryption)
      end
    end
    let(:metadata) do
      Saml::Kit::Metadata.build(configuration: configuration, &:build_identity_provider)
    end

    before { allow(registry).to receive(:metadata_for).and_return(metadata) }

    specify { expect(subject.build).to be_valid }
    specify { expect(subject.build.issuer).to eql(issuer) }
    specify { expect(subject.build.name_id).to eql(user.name_id) }
    specify { expect(subject.build.name_id_format).to eql(Saml::Kit::Namespaces::EMAIL_ADDRESS) }
    specify { expect(subject.build).to be_signed }
    specify { expect(subject.build).not_to be_expired }
    specify { expect(subject.build).to be_active }
    specify { expect(subject.build).not_to be_encrypted }
    specify { expect(subject.build.conditions.audiences).to include(issuer) }
    specify { expect(subject.build.attributes).to eql('email' => user.attributes[:email], 'created_at' => user.attributes[:created_at]) }
  end
end
