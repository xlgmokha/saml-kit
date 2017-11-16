require 'spec_helper'

RSpec.describe Saml::Kit::Binding do
  describe "#serialize" do
    let(:relay_state) { "ECHO" }
    let(:location) { FFaker::Internet.http_url }

    describe "HTTP-REDIRECT BINDING" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::HTTP_REDIRECT, location: location) }

      it 'encodes the request using the HTTP-Redirect encoding' do
        url, _ = subject.serialize(Saml::Kit::AuthenticationRequest, relay_state: relay_state)
        expect(url).to start_with(location)
        expect(url).to have_query_param('SAMLRequest')
        expect(url).to have_query_param('SigAlg')
        expect(url).to have_query_param('Signature')
      end
    end

    describe "HTTP-POST Binding" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::POST, location: location) }

      it 'encodes the request using the HTTP-POST encoding' do
        url, saml_params = subject.serialize(Saml::Kit::AuthenticationRequest, relay_state: relay_state)

        expect(url).to eql(location)
        expect(saml_params['RelayState']).to eql(relay_state)
        expect(saml_params['SAMLRequest']).to be_present
        xml = Hash.from_xml(Base64.decode64(saml_params['SAMLRequest']))
        expect(xml['AuthnRequest']).to be_present
        expect(xml['AuthnRequest']['Destination']).to eql(location)
        expect(xml['AuthnRequest']['Signature']).to be_present
      end
    end
  end
end
