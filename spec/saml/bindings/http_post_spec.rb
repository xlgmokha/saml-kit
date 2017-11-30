require 'spec_helper'

RSpec.describe Saml::Kit::Bindings::HttpPost do
  let(:location) { FFaker::Internet.http_url }
  subject { described_class.new(location: location) }

  describe "#serialize" do
    let(:relay_state) { "ECHO" }

    it 'encodes the request using the HTTP-POST encoding for a AuthenticationRequest' do
      builder = Saml::Kit::Builders::AuthenticationRequest.new
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
      builder = Saml::Kit::LogoutRequest::Builder.new(user)
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
      builder = Saml::Kit::LogoutResponse::Builder.new(user, request)
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
      builder = Saml::Kit::Builders::AuthenticationRequest.new
      url, saml_params = subject.serialize(builder)

      expect(url).to eql(location)
      expect(saml_params.keys).to_not include('RelayState')
    end
  end

  describe "#deserialize" do
    it 'deserializes to an AuthnRequest' do
      builder = Saml::Kit::Builders::AuthenticationRequest.new
      _, params = subject.serialize(builder)
      result = subject.deserialize(params)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes to a LogoutRequest' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      builder = Saml::Kit::LogoutRequest::Builder.new(user)
      _, params = subject.serialize(builder)
      result = subject.deserialize(params)
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
    end

    it 'deserializes to a Response' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: nil, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url, signed?: true, trusted?: true)
      builder = Saml::Kit::Response::Builder.new(user, request)
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
