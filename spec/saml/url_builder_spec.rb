require 'spec_helper'

RSpec.describe Saml::Kit::UrlBuilder do
  describe "#build" do
    let(:xml) { "<xml></xml>" }
    let(:destination) { FFaker::Internet.http_url }
    let(:relay_state) { FFaker::Movie.title }

    [
      [Saml::Kit::AuthenticationRequest, 'SAMLRequest'],
      [Saml::Kit::LogoutRequest, 'SAMLRequest'],
      [Saml::Kit::Response, 'SAMLResponse'],
      [Saml::Kit::LogoutResponse, 'SAMLResponse'],
    ].each do |(response_type, query_string_parameter)|
      describe response_type.to_s do
        let(:response) { instance_double(response_type, destination: destination, to_xml: xml, query_string_parameter: query_string_parameter) }
        let(:result) { subject.build(response, binding: :http_redirect, relay_state: relay_state) }
        let(:result_uri) { URI.parse(result) }
        let(:query_params) { Hash[result_uri.query.split("&").map { |x| x.split('=', 2) }] }

        it 'returns a url containing the target location' do
          expect(result_uri.scheme).to eql("http")
          expect(result_uri.host).to eql(URI.parse(destination).host)
        end

        it 'includes the message deflated (without header and checksum), base64-encoded, and URL-encoded' do
          level = Zlib::BEST_COMPRESSION
          expected = URI.encode(Base64.encode64(Zlib::Deflate.deflate(xml, level)[2..-5]).gsub(/\n/, ''))
          expect(result).to include("#{query_string_parameter}=#{expected}")
          expect(query_params[query_string_parameter]).to eql(expected)
        end

        it 'includes the relay state' do
          expect(query_params['RelayState']).to eql(URI.encode(relay_state))
          expect(result).to include("RelayState=#{URI.encode(relay_state)}")
        end

        it 'includes a signature' do
          expect(query_params['SigAlg']).to eql(URI.encode(Saml::Kit::Namespaces::SHA256))

          payload = "#{query_string_parameter}=#{query_params[query_string_parameter]}"
          payload << "&RelayState=#{query_params['RelayState']}"
          payload << "&SigAlg=#{query_params['SigAlg']}"
          expected_signature = Base64.strict_encode64(Saml::Kit.configuration.signing_private_key.sign(OpenSSL::Digest::SHA256.new, payload))
          expect(query_params['Signature']).to eql(expected_signature)
        end
      end
    end
  end
end
