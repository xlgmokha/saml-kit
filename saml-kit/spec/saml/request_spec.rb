require 'spec_helper'

RSpec.describe Saml::Kit::Request do
  describe ".deserialize" do
    subject { described_class }
    let(:issuer) { FFaker::Internet.http_url }
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:service_provider_metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(service_provider_metadata)
      allow(service_provider_metadata).to receive(:matches?).and_return(true)
      allow(service_provider_metadata).to receive(:assertion_consumer_services).and_return([
        { location: FFaker::Internet.http_url, binding: Saml::Kit::Namespaces::POST }
      ])
    end

    it 'decodes the raw_request' do
      builder = Saml::Kit::AuthenticationRequest::Builder.new
      builder.issuer = issuer
      raw_saml = builder.build.serialize

      result = subject.deserialize(raw_saml)
      expect(result.issuer).to eql(issuer)
      expect(result).to be_valid
    end

    it 'returns an invalid request when the raw request is corrupted' do
      expect(subject.deserialize("nonsense")).to be_invalid
    end

    it 'returns a logout request' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      builder = Saml::Kit::LogoutRequest::Builder.new(user)

      result = subject.deserialize(builder.build.serialize)
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
      expect(result.name_id).to eql(user.name_id_for)
    end

    [
      'fZFPa4QwEMW/iuTumqymroMKC1IQ2lLa0kMvJXUjCjGxmbF/vn2je9le9jpvfm/mzZSoJjPDcaHBPunPRSNFP5OxCJtQscVbcApHBKsmjUAdPB/v72C/4zB7R65zhl0g1wmFqD2NzrKobSr2ngmlpS7yuJc8jbPikMfFjRDxh5SqF7w/5DJl0av2GJiKBYsAIi66tUjKUihxkceBEPJlnwLPgBdvLGpCjtEq2qiBaIYkMa5TZnBIIDnnCWpcTROrv1ldrqvD5uxrNfrZedqd9FeZXArl+VgPIVbbPDozdr/RrfOTouup18p4ivutFeY1DZK2xJL6POD/A+o/&RelayState=%7B"redirect_to":"/"%7D&SigAlg=http://www.w3.org/2001/04/xmlenc%23sha256&Signature=dcM/kfdrERjZ+Q+WpzBTvk3RLVeEM5qGEM5ONJ/r4fxvEtMQyk6nT7PNZGsox0XYv+myi2yPBsqYUNC2kVii/uc34dn9l7Voyu6dGsNQPNTOpEwRHHILdjJUqhxEDBpd49vVbgdlF++pQZ7l74bUw8FdIbJ7W4EcOBQ1ffNtWTQNLv9n/D/jYKeGtJtaf61x8zDOlCyBwNi861bKXNFScyOwEFNcpVsgBIYhqZqKUWQVAcgYiGH5r16mtWFcT8NdnIvtICrN5VBpepK/ARnawhM6KhacQYllMpnXgbtsJcyQrRf1s9hqrkos1mRwgKLawZ5NjmF66dw3mKKs22b9NQ==',
      'fZFNb4MwDIb/CsqdJtBSWguQKqFJSNs0bdMOvUxZCCISJCw2+/j3C/TSXXrxwfbz2q9doByHCU4z9fZZf84aKfoZB4uwFko2ewtOokGwctQIpODl9HAP6UbA5B055QZ2hdwmJKL2ZJxlUVOX7H1/VEe12+s4y8RHvNuGcNRdHh8OoutUkudt17LoTXsMTMmCRAARZ91YJGkppESSx0kSJ9lruoUkBZGdWVQHH8ZKWqmeaALOB6fk0DskyIQQHDUuotzqb1YVy+qwKvtKGj85T5tWfxX8ulBcjvUYbDX1kxuM+o3unB8l3Xa9ZEwbd2srTIsbJG2J8eoy4P8Dqj8=&RelayState=%7B"redirect_to":"/"%7D&SigAlg=http://www.w3.org/2001/04/xmlenc%23sha256&Signature=sI50KhkFGLxFBnuWCZ4gJ+FrG5mY4f5f4afjdRc0lFHdgzMlJt9xzqh39ufHAkhpi2+OdWjg87pwpPgfz3das4QJMMenb/o5vNnFGqt2OMiyjoQbVc7b5xSA78FU+OlwqK3XgGdqo3KrRL+AJuagm4D3VeSbZhZ/0zPm1RG0/spCuxx+BbFwTW0BI+VU9+1zkmdV1CJt8kYtmNdvYavgD7rcUX2MWgaRVR+t/nNND5Wmdoxxfp/pzhkjrjt20+TpkDI9sKWlUSOZnATDFO/KlnKSvn/LrQ8wofqHViRksMhDIvVD9mNu7tJaQ6NB1yPUrmsOblPtAmRuBDBgChdHRA==',
      'fZFPa4QwEMW/iuSejdFVy6DCghSEtpS29NDLko1ZFDSxmbF/vn2je9le9jpvfm/mzZSopnGGw0K9fTGfi0GKfqbRImxCxRZvwSkcEKyaDAJpeD08PkCyi2H2jpx2I7tCbhMK0XganGVR21TsGJ/yNM2V5jI/dXwvz4rfpUXCU53LRGdpoZOMRe/GY2AqFiwCiLiY1iIpS6EUy4JLyWX2lqQg9yDlB4uakGOwijaqJ5pBiNFpNfYOCbI4jgUaXE2FNd+sLtfVYXP2tRr87DztOvNVimuhvBzrKcRqm2c3Dvo3und+UnQ79VoZOn7eWmFe0yAZS0zUlwH/H1D/AQ==&RelayState=%7B"redirect_to":"/"%7D&SigAlg=http://www.w3.org/2001/04/xmlenc%23sha256&Signature=vNIzNWsCqdi2rs5HMRWSm+udc42K9sCm/epeV212sP4vYwot9K9xvoz8Z7jvY8zsY2BPdjZsEJPpHjPKb4+xB+riyc5fUP5wUEUSsQF5Q5FtoQx0jJbcNDadHoTdH1IEiQazTt7ED6sYmnY93lxqFtRkoUtov6XGXRT6ypNRGRFqn5T4JYZEROhdLRAOSCyoOjZ8kPcWKGP1Fo0+A25bwl1Yo3tqBTZsc522AaLhK/6f7uLftSUaTMA0lnmQqRXzZrfjVtDAHa5JSHLH2eh7vZavyvmqApshL1qHEihRN9VFx7DPjRspvp8pIn/8CH18ynVzzKPxIUOl3Kt4QNsVJA==',
    ].each do |saml|
      it do
        expect(subject.deserialize(saml)).to be_instance_of(Saml::Kit::AuthenticationRequest)
      end
    end
  end
end
