require 'spec_helper'

RSpec.describe Saml::Kit::Bindings::HttpRedirect do
  let(:location) { FFaker::Internet.http_url }
  subject { described_class.new(location: location) }

  describe "#serialize" do
    let(:relay_state) { "ECHO" }

    it 'encodes the request using the HTTP-Redirect encoding' do
      builder = Saml::Kit::Builders::AuthenticationRequest.new
      url, _ = subject.serialize(builder, relay_state: relay_state)
      expect(url).to start_with(location)
      expect(url).to have_query_param('SAMLRequest')
      expect(url).to have_query_param('SigAlg')
      expect(url).to have_query_param('Signature')
    end
  end

  describe "#deserialize" do
    let(:issuer) { FFaker::Internet.http_url }
    let(:provider) { Saml::Kit::Builders::IdentityProviderMetadata.new.build }

    before :each do
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest' do
      url, _ = subject.serialize(Saml::Kit::Builders::AuthenticationRequest.new)
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the SAMLRequest to a LogoutRequest' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      url, _ = subject.serialize(Saml::Kit::LogoutRequest::Builder.new(user))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
    end

    it 'returns an invalid request when the SAMLRequest is invalid' do
      expect do
        subject.deserialize({ 'SAMLRequest' => "nonsense" })
      end.to raise_error(Zlib::DataError)
    end

    it 'deserializes the SAMLResponse to a Response' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: nil, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: issuer, signed?: true, trusted?: true)
      url, _ = subject.serialize(Saml::Kit::Response::Builder.new(user, request))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::Response)
    end

    it 'deserializes the SAMLResponse to a LogoutResponse' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: provider, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url)
      url, _ = subject.serialize(Saml::Kit::LogoutResponse::Builder.new(user, request))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::LogoutResponse)
    end

    it 'raise an error when the content is invalid' do
      expect do
        subject.deserialize({ 'SAMLResponse' => "nonsense" })
      end.to raise_error(Zlib::DataError)
    end

    it 'raises an error when a saml parameter is not specified' do
      expect do
        subject.deserialize({ })
      end.to raise_error(ArgumentError)
    end

    it 'raises an error when the signature does not match' do
      url, _ = subject.serialize(Saml::Kit::Builders::AuthenticationRequest.new)
      query_params = query_params_from(url)
      query_params['Signature'] = 'invalid'
      expect do
        subject.deserialize(query_params)
      end.to raise_error(/Invalid Signature/)
    end

    it 'returns a signed document, when a signature is missing' do
      builder = Saml::Kit::ServiceProviderMetadata::Builder.new
      builder.add_assertion_consumer_service(FFaker::Internet.http_url, binding: :http_post)
      provider = builder.build
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)

      url, _ = subject.serialize(Saml::Kit::Builders::AuthenticationRequest.new)
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
      expect(result).to be_valid
    end
  end
end
