require 'spec_helper'

RSpec.describe Saml::Kit::Bindings::HttpPost do
  let(:location) { FFaker::Internet.uri("https") }
  subject { described_class.new(location: location) }

  describe "equality" do
    it 'is referentially equal' do
      expect(subject).to eql(subject)
    end

    it 'is equal by value' do
      expect(subject).to eql(
        Saml::Kit::Bindings::HttpPost.new(location: location)
      )
    end

    it 'is not equal' do
      expect(subject).to_not eql(
        described_class.new(location: FFaker::Internet.uri("https"))
      )
    end
  end

  describe "#serialize" do
    let(:relay_state) { "ECHO" }
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.generate_key_pair_for(use: :signing)
      end
    end

    it 'encodes the request using the HTTP-POST encoding for a AuthenticationRequest' do
      builder = Saml::Kit::AuthenticationRequest.builder_class.new(configuration: configuration)
      url, saml_params = subject.serialize(builder, relay_state: relay_state)

      expect(url).to eql(location)
      expect(saml_params['RelayState']).to eql(relay_state)
      expect(saml_params['SAMLRequest']).to be_present
      xml = Hash.from_xml(Base64.decode64(saml_params['SAMLRequest']))
      expect(xml['AuthnRequest']).to be_present
      expect(xml['AuthnRequest']['Destination']).to eql(location)
      expect(xml['AuthnRequest']['Signature']).to be_present
    end

    it 'returns a SAMLRequest for a LogoutRequest' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      builder = Saml::Kit::LogoutRequest.builder_class.new(user, configuration: configuration)
      url, saml_params = subject.serialize(builder, relay_state: relay_state)

      expect(url).to eql(location)
      expect(saml_params['RelayState']).to eql(relay_state)
      expect(saml_params['SAMLRequest']).to be_present
      xml = Hash.from_xml(Base64.decode64(saml_params['SAMLRequest']))
      expect(xml['LogoutRequest']).to be_present
      expect(xml['LogoutRequest']['Destination']).to eql(location)
      expect(xml['LogoutRequest']['Signature']).to be_present
    end

    it 'returns a SAMLResponse for a LogoutResponse' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      request = instance_double(Saml::Kit::AuthenticationRequest, id: SecureRandom.uuid)
      builder = Saml::Kit::LogoutResponse.builder_class.new(user, request, configuration: configuration)
      url, saml_params = subject.serialize(builder, relay_state: relay_state)

      expect(url).to eql(location)
      expect(saml_params['RelayState']).to eql(relay_state)
      expect(saml_params['SAMLResponse']).to be_present
      xml = Hash.from_xml(Base64.decode64(saml_params['SAMLResponse']))
      expect(xml['LogoutResponse']).to be_present
      expect(xml['LogoutResponse']['Destination']).to eql(location)
      expect(xml['LogoutResponse']['Signature']).to be_present
    end

    it 'excludes the RelayState when blank' do
      builder = Saml::Kit::AuthenticationRequest.builder_class.new
      url, saml_params = subject.serialize(builder)

      expect(url).to eql(location)
      expect(saml_params.keys).to_not include('RelayState')
    end
  end

  describe "#deserialize" do
    it 'deserializes to an AuthnRequest' do
      builder = Saml::Kit::AuthenticationRequest.builder_class.new
      _, params = subject.serialize(builder)
      result = subject.deserialize(params)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes to a LogoutRequest' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      builder = Saml::Kit::LogoutRequest.builder_class.new(user)
      _, params = subject.serialize(builder)
      result = subject.deserialize(params)
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
    end

    it 'deserializes to a Response' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: nil, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url, signed?: true, trusted?: true)
      builder = Saml::Kit::Response.builder_class.new(user, request)
      _, params = subject.serialize(builder)
      result = subject.deserialize(params)
      expect(result).to be_instance_of(Saml::Kit::Response)
    end

    it 'raises an error when SAMLRequest and SAMLResponse are missing' do
      expect do
        subject.deserialize({})
      end.to raise_error(/SAMLRequest or SAMLResponse parameter is required/)
    end
  end
end
