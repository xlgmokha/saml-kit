require 'spec_helper'

RSpec.describe Saml::Kit::Bindings::HttpRedirect do
  let(:location) { FFaker::Internet.http_url }
  subject { described_class.new(location: location) }

  describe "#serialize" do
    let(:relay_state) { "ECHO" }
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.generate_key_pair_for(use: :signing)
      end
    end

    it 'encodes the request using the HTTP-Redirect encoding' do
      builder = Saml::Kit::AuthenticationRequest.builder_class.new(configuration: configuration)
      url, _ = subject.serialize(builder, relay_state: relay_state)
      expect(url).to start_with(location)
      expect(url).to have_query_param('SAMLRequest')
      expect(url).to have_query_param('SigAlg')
      expect(url).to have_query_param('Signature')
    end
  end

  describe "#deserialize" do
    let(:issuer) { FFaker::Internet.http_url }
    let(:provider) { Saml::Kit::IdentityProviderMetadata.build }

    before :each do
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest' do
      url, _ = subject.serialize(Saml::Kit::AuthenticationRequest.builder_class.new)
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest with symbols for keys' do
      url, _ = subject.serialize(Saml::Kit::AuthenticationRequest.builder_class.new)
      result = subject.deserialize(query_params_from(url).symbolize_keys)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the SAMLRequest to a LogoutRequest' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      url, _ = subject.serialize(Saml::Kit::LogoutRequest.builder_class.new(user))
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
      request = double(:request, id: SecureRandom.uuid, provider: nil, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: issuer, signed?: true, trusted?: true)
      url, _ = subject.serialize(Saml::Kit::Response.builder_class.new(user, request))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::Response)
    end

    it 'deserializes the SAMLResponse to a LogoutResponse' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: provider, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url)
      url, _ = subject.serialize(Saml::Kit::LogoutResponse.builder_class.new(user, request))
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
      url, _ = subject.serialize(Saml::Kit::AuthenticationRequest.builder_class.new)
      query_params = query_params_from(url)
      query_params['Signature'] = 'invalid'
      expect do
        subject.deserialize(query_params)
      end.to raise_error(/Invalid Signature/)
    end

    it 'returns a signed document, when a signature is missing' do
      provider = Saml::Kit::ServiceProviderMetadata.build do |builder|
        builder.add_assertion_consumer_service(FFaker::Internet.http_url, binding: :http_post)
      end
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)

      url, _ = subject.serialize(Saml::Kit::AuthenticationRequest.builder_class.new)
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
      expect(result).to be_valid
    end
  end
end
