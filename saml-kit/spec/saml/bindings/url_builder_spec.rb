require 'spec_helper'

RSpec.describe Saml::Kit::Bindings::UrlBuilder do
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

        def to_query_params(url)
          Hash[URI.parse(url).query.split("&").map { |x| x.split('=', 2) }]
        end

        it 'returns a url containing the target location' do
          result_uri = URI.parse(subject.build(response))
          expect(result_uri.scheme).to eql("http")
          expect(result_uri.host).to eql(URI.parse(destination).host)
        end

        it 'includes the message deflated (without header and checksum), base64-encoded, and URL-encoded' do
          result = subject.build(response, relay_state: relay_state)
          query_params = to_query_params(result)
          level = Zlib::BEST_COMPRESSION
          expected = CGI.escape(Base64.encode64(Zlib::Deflate.deflate(xml, level)[2..-5]).gsub(/\n/, ''))
          expect(result).to include("#{query_string_parameter}=#{expected}")
          expect(query_params[query_string_parameter]).to eql(expected)
        end

        it 'includes the relay state' do
          result = subject.build(response, relay_state: relay_state)
          query_params = to_query_params(result)
          expect(query_params['RelayState']).to eql(CGI.escape(relay_state))
          expect(result).to include("RelayState=#{CGI.escape(relay_state)}")
        end

        it 'excludes the relay state' do
          query_params = to_query_params(subject.build(response))
          expect(query_params['RelayState']).to be_nil
        end

        it 'includes a signature' do
          result = subject.build(response, relay_state: relay_state)
          query_params = to_query_params(result)
          expect(query_params['SigAlg']).to eql(CGI.escape(Saml::Kit::Namespaces::SHA256))

          payload = "#{query_string_parameter}=#{query_params[query_string_parameter]}"
          payload << "&RelayState=#{query_params['RelayState']}"
          payload << "&SigAlg=#{query_params['SigAlg']}"
          expected_signature = Base64.strict_encode64(Saml::Kit.configuration.signing_private_key.sign(OpenSSL::Digest::SHA256.new, payload))
          expect(query_params['Signature']).to eql(expected_signature)
        end

        it 'generates the signature correctly when the relay state is absent' do
          result = subject.build(response)
          query_params = to_query_params(result)
          expect(query_params['SigAlg']).to eql(CGI.escape(Saml::Kit::Namespaces::SHA256))

          payload = "#{query_string_parameter}=#{query_params[query_string_parameter]}"
          payload << "&SigAlg=#{query_params['SigAlg']}"
          expected_signature = Base64.strict_encode64(Saml::Kit.configuration.signing_private_key.sign(OpenSSL::Digest::SHA256.new, payload))
          expect(query_params['Signature']).to eql(expected_signature)
        end
      end
    end
  end
end
