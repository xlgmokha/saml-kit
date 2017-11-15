require 'spec_helper'

RSpec.describe Saml::Kit::UrlBuilder do
  describe "#build" do
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, destination: destination, to_xml: xml) }
    let(:xml) { "<xml></xml>" }
    let(:destination) { FFaker::Internet.http_url }
    let(:relay_state) { FFaker::Movie.title }
    let(:query_params) { Hash[result_uri.query.split("&").map { |x| x.split('=', 2) }] }
    let(:result) { subject.build(request, binding: :http_redirect, relay_state: relay_state) }
    let(:result_uri) { URI.parse(result) }

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

<<-DOC
2. To construct the signature, a string consisting of the concatenation of the RelayState 
(if present), SigAlg, and SAMLRequest (or SAMLResponse) query string parameters 
(each one URLencoded) is constructed in one of the following ways (ordered as below):

SAMLRequest=value&RelayState=value&SigAlg=value
SAMLResponse=value&RelayState=value&SigAlg=value

3. The resulting string of bytes is the octet string to be fed into the signature algorithm.
Any other content in the original query string is not included and not signed.
4. The signature value MUST be encoded using the base64 encoding (see RFC 2045 [RFC2045]) with
any whitespace removed, and included as a query string parameter named Signature.
DOC
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
