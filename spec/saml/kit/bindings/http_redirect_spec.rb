RSpec.describe Saml::Kit::Bindings::HttpRedirect do
  subject { described_class.new(location: location) }

  let(:location) { FFaker::Internet.http_url }

  describe '#serialize' do
    let(:relay_state) { 'ECHO' }
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.generate_key_pair_for(use: :signing)
      end
    end

    it 'encodes the request using the HTTP-Redirect encoding' do
      builder = Saml::Kit::AuthenticationRequest.builder(configuration: configuration)
      url, = subject.serialize(builder, relay_state: relay_state)
      expect(url).to start_with(location)
      expect(url).to have_query_param('SAMLRequest')
      expect(url).to have_query_param('SigAlg')
      expect(url).to have_query_param('Signature')
    end
  end

  describe '#deserialize' do
    let(:entity_id) { FFaker::Internet.http_url }
    let(:provider) { Saml::Kit::IdentityProviderMetadata.build }

    before do
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(entity_id).and_return(provider)
      allow(Saml::Kit.configuration).to receive(:entity_id).and_return(entity_id)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest' do
      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder)
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the raw query_string to an AuthnRequest' do
      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder, relay_state: 'HELLO')
      result = subject.deserialize(url)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest with symbols for keys' do
      configuration = Saml::Kit::Configuration.new do |config|
        config.entity_id = entity_id
        config.generate_key_pair_for(use: :signing)
      end
      provider = Saml::Kit::IdentityProviderMetadata.build(configuration: configuration)
      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder(configuration: configuration))
      allow(configuration.registry).to receive(:metadata_for).with(entity_id).and_return(provider)

      result = subject.deserialize(query_params_from(url).symbolize_keys, configuration: configuration)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
      expect(result).to be_signed
      expect(result).to be_trusted
    end

    it 'deserializes the SAMLRequest to an AuthnRequest with symbols for keys' do
      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder)
      result = subject.deserialize(query_params_from(url).symbolize_keys)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the SAMLRequest to an AuthnRequest when given a custom params object' do
      class Parameters
        def initialize(params)
          @params = params
        end

        def [](key)
          @params[key]
        end
      end
      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder)
      result = subject.deserialize(Parameters.new(query_params_from(url)))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'deserializes the SAMLRequest to a LogoutRequest' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      url, = subject.serialize(Saml::Kit::LogoutRequest.builder(user))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
    end

    it 'returns an invalid request when the SAMLRequest is invalid' do
      expect do
        subject.deserialize('SAMLRequest' => 'nonsense')
      end.to raise_error(Zlib::DataError)
    end

    it 'deserializes the SAMLResponse to a Response' do
      user = double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: [])
      request = double(:request, id: SecureRandom.uuid, provider: nil, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: entity_id, signed?: true, trusted?: true)
      url, = subject.serialize(Saml::Kit::Response.builder(user, request))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::Response)
    end

    it 'deserializes the SAMLResponse to a LogoutResponse' do
      request = double(:request, id: SecureRandom.uuid, provider: provider, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url)
      url, = subject.serialize(Saml::Kit::LogoutResponse.builder(request))
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::LogoutResponse)
    end

    it 'raises an error when the content is invalid' do
      expect do
        subject.deserialize('SAMLResponse' => 'nonsense')
      end.to raise_error(Zlib::DataError)
    end

    it 'raises an error when a saml parameter is not specified' do
      expect do
        subject.deserialize({})
      end.to raise_error(ArgumentError)
    end

    it 'raises an error when the signature does not match' do
      configuration = Saml::Kit::Configuration.new do |config|
        config.entity_id = entity_id
        config.generate_key_pair_for(use: :signing)
      end
      url, = subject.serialize(
        Saml::Kit::AuthenticationRequest.builder(configuration: configuration) do |x|
          x.embed_signature = true
        end
      )
      query_params = query_params_from(url)
      query_params['Signature'] = 'invalid'
      expect do
        subject.deserialize(query_params)
      end.to raise_error(/Invalid Signature/)
    end

    it 'returns a signed document, when a signature is missing' do
      provider = Saml::Kit::ServiceProviderMetadata.build do |builder|
        builder.add_assertion_consumer_service(FFaker::Internet.http_url, binding: :http_post)
      end
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(entity_id).and_return(provider)

      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder)
      result = subject.deserialize(query_params_from(url))
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
      expect(result).to be_valid
    end

    it 'returns an unverfied document when the provider is unknown' do
      configuration = Saml::Kit::Configuration.new do |config|
        config.generate_key_pair_for(use: :signing)
      end
      url, = subject.serialize(Saml::Kit::AuthenticationRequest.builder(configuration: configuration))

      other_configuration = Saml::Kit::Configuration.new
      allow(other_configuration.registry).to receive(:metadata_for).and_return(nil)

      result = subject.deserialize(query_params_from(url), configuration: other_configuration)
      expect(result).not_to be_signed
      expect(result).not_to be_trusted
    end
  end
end
