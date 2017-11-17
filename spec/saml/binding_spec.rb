require 'spec_helper'

RSpec.describe Saml::Kit::Binding do
  let(:location) { FFaker::Internet.http_url }

  describe "#serialize" do
    let(:relay_state) { "ECHO" }

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

      it 'excludes the RelayState when blank' do
        builder = Saml::Kit::AuthenticationRequest::Builder.new
        url, saml_params = subject.serialize(builder)

        expect(url).to eql(location)
        expect(saml_params.keys).to_not include('RelayState')
      end
    end

    it 'ignores other bindings' do
      subject = Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::HTTP_ARTIFACT, location: location)
      expect(subject.serialize(Saml::Kit::AuthenticationRequest)).to be_empty
    end
  end

  describe "#deserialize" do
    describe "HTTP-Redirect binding" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::HTTP_REDIRECT, location: location) }
      let(:issuer) { FFaker::Internet.http_url }
      let(:provider) { Saml::Kit::IdentityProviderMetadata::Builder.new.build }

      before :each do
        allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)
        allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
      end

      it 'deserializes the SAMLRequest to an AuthnRequest' do
        url, _ = subject.serialize(Saml::Kit::AuthenticationRequest::Builder.new)
        result = subject.deserialize(query_params_from(url))
        expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
      end

      it 'deserializes the SAMLRequest to a LogoutRequest' do
        user = double(:user, name_id_for: SecureRandom.uuid)
        url, _ = subject.serialize(Saml::Kit::LogoutRequest::Builder.new(user))
        result = subject.deserialize(query_params_from(url))
        expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
      end

      it 'returns an invalid request when the SAMLRequest is invalid' do
        result = subject.deserialize({ 'SAMLRequest' => "nonsense" })
        expect(result).to be_instance_of(Saml::Kit::InvalidRequest)
      end

      it 'deserializes the SAMLResponse to a Response' do
        user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
        request = double(:request, id: SecureRandom.uuid, provider: nil, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: issuer)
        url, _ = subject.serialize(Saml::Kit::Response::Builder.new(user, request))
        result = subject.deserialize(query_params_from(url))
        expect(result).to be_instance_of(Saml::Kit::Response)
      end

      it 'deserializes the SAMLResponse to a LogoutResponse' do
        user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
        request = double(:request, id: SecureRandom.uuid, provider: provider, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url)
        url, _ = subject.serialize(Saml::Kit::LogoutResponse::Builder.new(user, request))
        result = subject.deserialize(query_params_from(url))
        expect(result).to be_instance_of(Saml::Kit::LogoutResponse)
      end

      it 'returns an invalid response when the SAMLResponse is invalid' do
        result = subject.deserialize({ 'SAMLResponse' => "nonsense" })
        expect(result).to be_instance_of(Saml::Kit::InvalidResponse)
      end

      it 'raises an error when a saml parameter is not specified' do
        expect do
          subject.deserialize({ })
        end.to raise_error(ArgumentError)
      end

      it 'raises an error when the signature does not match' do
        url, _ = subject.serialize(Saml::Kit::AuthenticationRequest::Builder.new)
        query_params = query_params_from(url)
        query_params['Signature'] = 'invalid'
        expect do
          subject.deserialize(query_params)
        end.to raise_error(/Invalid Signature/)
      end
    end

    describe "HTTP Post binding" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::POST, location: location) }

      it 'deserializes to an AuthnRequest' do
        builder = Saml::Kit::AuthenticationRequest::Builder.new
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
        request = double(:request, id: SecureRandom.uuid, provider: nil, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url)
        builder = Saml::Kit::Response::Builder.new(user, request)
        _, params = subject.serialize(builder)
        result = subject.deserialize(params)
        expect(result).to be_instance_of(Saml::Kit::Response)
      end

      it 'raises an error when SAMLRequest and SAMLResponse are missing' do
        expect do
          subject.deserialize({})
        end.to raise_error(/Missing SAMLRequest or SAMLResponse/)
      end

      [
        'fZFPa4QwEMW/iuTumqymroMKC1IQ2lLa0kMvJXUjCjGxmbF/vn2je9le9jpvfm/mzZSoJjPDcaHBPunPRSNFP5OxCJtQscVbcApHBKsmjUAdPB/v72C/4zB7R65zhl0g1wmFqD2NzrKobSr2ngmlpS7yuJc8jbPikMfFjRDxh5SqF7w/5DJl0av2GJiKBYsAIi66tUjKUihxkceBEPJlnwLPgBdvLGpCjtEq2qiBaIYkMa5TZnBIIDnnCWpcTROrv1ldrqvD5uxrNfrZedqd9FeZXArl+VgPIVbbPDozdr/RrfOTouup18p4ivutFeY1DZK2xJL6POD/A+o/&RelayState=%7B"redirect_to":"/"%7D&SigAlg=http://www.w3.org/2001/04/xmlenc%23sha256&Signature=dcM/kfdrERjZ+Q+WpzBTvk3RLVeEM5qGEM5ONJ/r4fxvEtMQyk6nT7PNZGsox0XYv+myi2yPBsqYUNC2kVii/uc34dn9l7Voyu6dGsNQPNTOpEwRHHILdjJUqhxEDBpd49vVbgdlF++pQZ7l74bUw8FdIbJ7W4EcOBQ1ffNtWTQNLv9n/D/jYKeGtJtaf61x8zDOlCyBwNi861bKXNFScyOwEFNcpVsgBIYhqZqKUWQVAcgYiGH5r16mtWFcT8NdnIvtICrN5VBpepK/ARnawhM6KhacQYllMpnXgbtsJcyQrRf1s9hqrkos1mRwgKLawZ5NjmF66dw3mKKs22b9NQ==',
        'fZFNb4MwDIb/CsqdJtBSWguQKqFJSNs0bdMOvUxZCCISJCw2+/j3C/TSXXrxwfbz2q9doByHCU4z9fZZf84aKfoZB4uwFko2ewtOokGwctQIpODl9HAP6UbA5B055QZ2hdwmJKL2ZJxlUVOX7H1/VEe12+s4y8RHvNuGcNRdHh8OoutUkudt17LoTXsMTMmCRAARZ91YJGkppESSx0kSJ9lruoUkBZGdWVQHH8ZKWqmeaALOB6fk0DskyIQQHDUuotzqb1YVy+qwKvtKGj85T5tWfxX8ulBcjvUYbDX1kxuM+o3unB8l3Xa9ZEwbd2srTIsbJG2J8eoy4P8Dqj8=&RelayState=%7B"redirect_to":"/"%7D&SigAlg=http://www.w3.org/2001/04/xmlenc%23sha256&Signature=sI50KhkFGLxFBnuWCZ4gJ+FrG5mY4f5f4afjdRc0lFHdgzMlJt9xzqh39ufHAkhpi2+OdWjg87pwpPgfz3das4QJMMenb/o5vNnFGqt2OMiyjoQbVc7b5xSA78FU+OlwqK3XgGdqo3KrRL+AJuagm4D3VeSbZhZ/0zPm1RG0/spCuxx+BbFwTW0BI+VU9+1zkmdV1CJt8kYtmNdvYavgD7rcUX2MWgaRVR+t/nNND5Wmdoxxfp/pzhkjrjt20+TpkDI9sKWlUSOZnATDFO/KlnKSvn/LrQ8wofqHViRksMhDIvVD9mNu7tJaQ6NB1yPUrmsOblPtAmRuBDBgChdHRA==',
        'fZFPa4QwEMW/iuSejdFVy6DCghSEtpS29NDLko1ZFDSxmbF/vn2je9le9jpvfm/mzZSopnGGw0K9fTGfi0GKfqbRImxCxRZvwSkcEKyaDAJpeD08PkCyi2H2jpx2I7tCbhMK0XganGVR21TsGJ/yNM2V5jI/dXwvz4rfpUXCU53LRGdpoZOMRe/GY2AqFiwCiLiY1iIpS6EUy4JLyWX2lqQg9yDlB4uakGOwijaqJ5pBiNFpNfYOCbI4jgUaXE2FNd+sLtfVYXP2tRr87DztOvNVimuhvBzrKcRqm2c3Dvo3und+UnQ79VoZOn7eWmFe0yAZS0zUlwH/H1D/AQ==&RelayState=%7B"redirect_to":"/"%7D&SigAlg=http://www.w3.org/2001/04/xmlenc%23sha256&Signature=vNIzNWsCqdi2rs5HMRWSm+udc42K9sCm/epeV212sP4vYwot9K9xvoz8Z7jvY8zsY2BPdjZsEJPpHjPKb4+xB+riyc5fUP5wUEUSsQF5Q5FtoQx0jJbcNDadHoTdH1IEiQazTt7ED6sYmnY93lxqFtRkoUtov6XGXRT6ypNRGRFqn5T4JYZEROhdLRAOSCyoOjZ8kPcWKGP1Fo0+A25bwl1Yo3tqBTZsc522AaLhK/6f7uLftSUaTMA0lnmQqRXzZrfjVtDAHa5JSHLH2eh7vZavyvmqApshL1qHEihRN9VFx7DPjRspvp8pIn/8CH18ynVzzKPxIUOl3Kt4QNsVJA==',
      ].each do |saml|
        it do
          expect(subject.deserialize('SAMLRequest' => saml)).to be_instance_of(Saml::Kit::AuthenticationRequest)
        end
      end
    end

    describe "Artifact binding" do
      let(:subject) { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::HTTP_ARTIFACT, location: location) }

      it 'raises an error' do
        expect do
          subject.deserialize('SAMLRequest' => "CORRUPT")
        end.to raise_error(/Unsupported binding/)
      end
    end
  end
end
