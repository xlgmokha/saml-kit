require 'spec_helper'

RSpec.describe Saml::Kit::HttpRedirectBinding do
  let(:location) { FFaker::Internet.http_url }

  describe "#serialize" do
    let(:relay_state) { "ECHO" }
    let(:subject) { Saml::Kit::HttpRedirectBinding.new(binding: Saml::Kit::Namespaces::HTTP_REDIRECT, location: location) }

    it 'encodes the request using the HTTP-Redirect encoding' do
      builder = Saml::Kit::AuthenticationRequest::Builder.new
      url, _ = subject.serialize(builder, relay_state: relay_state)
      expect(url).to start_with(location)
      expect(url).to have_query_param('SAMLRequest')
      expect(url).to have_query_param('SigAlg')
      expect(url).to have_query_param('Signature')
    end
  end

  describe "#deserialize" do
    let(:subject) { Saml::Kit::HttpRedirectBinding.new(binding: Saml::Kit::Namespaces::HTTP_REDIRECT, location: location) }
    let(:issuer) { FFaker::Internet.http_url }
    let(:provider) { Saml::Kit::IdentityProviderMetadata::Builder.new.build }

    before :each do
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest' do
      url, _ = subject.serialize(Saml::Kit::AuthenticationRequest::Builder.new)
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
      result = subject.deserialize({ 'SAMLRequest' => "nonsense" })
      expect(result).to be_instance_of(Saml::Kit::InvalidDocument)
    end

    it 'deserializes the SAMLResponse to a Response' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: nil, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: issuer)
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

    it 'returns an invalid response when the SAMLResponse is invalid' do
      result = subject.deserialize({ 'SAMLResponse' => "nonsense" })
      expect(result).to be_instance_of(Saml::Kit::InvalidDocument)
    end

    it 'raises an error when a saml parameter is not specified' do
      expect do
        subject.deserialize({ })
      end.to raise_error(ArgumentError)
    end

    it 'raises an error when the signature does not match' do
      url, _ = subject.serialize(Saml::Kit::AuthenticationRequest::Builder.new)
      query_params = query_params_from(url)
      query_params['Signature'] = 'invalid'
      expect do
        subject.deserialize(query_params)
      end.to raise_error(/Invalid Signature/)
    end
  end
end
