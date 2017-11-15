require 'spec_helper'

RSpec.describe Saml::Kit::UrlBuilder do
  describe "#build" do
    let(:xml) { "<xml></xml>" }
    let(:destination) { FFaker::Internet.http_url }
    let(:relay_state) { FFaker::Movie.title }
    let(:query_params) { Hash[result_uri.query.split("&").map { |x| x.split('=', 2) }] }
    let(:result) { subject.build(request, binding: :http_redirect, relay_state: relay_state) }
    let(:result_uri) { URI.parse(result) }

    [
      Saml::Kit::AuthenticationRequest,
      Saml::Kit::LogoutRequest,
    ].each do |request_type|
      describe "AuthnRequest" do
        let(:request) { instance_double(request_type, destination: destination, to_xml: xml) }

        it 'returns a url containing the target location' do
          expect(result_uri.scheme).to eql("http")
          expect(result_uri.host).to eql(URI.parse(destination).host)
        end

        it 'includes the message deflated (without header and checksum), base64-encoded, and URL-encoded' do
          level = Zlib::BEST_COMPRESSION
          expected = URI.encode(Base64.encode64(Zlib::Deflate.deflate(xml, level)[2..-5]).gsub(/\n/, ''))
          expect(result).to include("SAMLRequest=#{expected}")
          expect(query_params['SAMLRequest']).to eql(expected)
        end

        it 'includes the relay state' do
          expect(query_params['RelayState']).to eql(URI.encode(relay_state))
          expect(result).to include("RelayState=#{URI.encode(relay_state)}")
        end

        # https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf section 3.4.4.1
        it 'includes a signature' do
          expect(query_params['SigAlg']).to eql(URI.encode(Saml::Kit::Namespaces::SHA256))

          payload = "SAMLRequest=#{query_params['SAMLRequest']}"
          payload << "&RelayState=#{query_params['RelayState']}"
          payload << "&SigAlg=#{query_params['SigAlg']}"
          expected_signature = Base64.strict_encode64(Saml::Kit.configuration.signing_private_key.sign(OpenSSL::Digest::SHA256.new, payload))
          expect(query_params['Signature']).to eql(expected_signature)
        end
      end
    end
  end
end
