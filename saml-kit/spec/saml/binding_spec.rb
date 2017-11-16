require 'spec_helper'

RSpec.describe Saml::Kit::Binding do
  describe "#serialize" do
    let(:relay_state) { "ECHO" }
    let(:location) { FFaker::Internet.http_url }

    describe "HTTP-REDIRECT BINDING" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::HTTP_REDIRECT, location: location) }

      it 'encodes the request using the HTTP-Redirect encoding' do
        builder = Saml::Kit::AuthenticationRequest::Builder.new
        url, _ = subject.serialize(builder, relay_state: relay_state)
        expect(url).to start_with(location)
        expect(url).to have_query_param('SAMLRequest')
        expect(url).to have_query_param('SigAlg')
        expect(url).to have_query_param('Signature')
      end
    end

    describe "HTTP-POST Binding" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::POST, location: location) }

      it 'encodes the request using the HTTP-POST encoding for a AuthenticationRequest' do
        builder = Saml::Kit::AuthenticationRequest::Builder.new
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
    end

    it 'ignores other bindings' do
      subject = Saml::Kit::Binding.new(binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact', location: location)
      expect(subject.serialize(Saml::Kit::AuthenticationRequest)).to be_empty
    end
  end
end
