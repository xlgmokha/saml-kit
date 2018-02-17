RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml, configuration: configuration) }

  let(:id) { Xml::Kit::Id.generate }
  let(:assertion_consumer_service_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:destination) { FFaker::Internet.http_url }
  let(:name_id_format) { Saml::Kit::Namespaces::EMAIL_ADDRESS }
  let(:raw_xml) do
    described_class.build_xml(configuration: configuration) do |builder|
      builder.id = id
      builder.now = Time.now.utc
      builder.issuer = issuer
      builder.assertion_consumer_service_url = assertion_consumer_service_url
      builder.name_id_format = name_id_format
      builder.destination = destination
    end
  end
  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.generate_key_pair_for(use: :signing)
    end
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql(id) }
  it { expect(subject.assertion_consumer_service_url).to eql(assertion_consumer_service_url) }
  it { expect(subject.name_id_format).to eql(name_id_format) }
  it { expect(subject.destination).to eql(destination) }

  describe '#valid?' do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { Saml::Kit::ServiceProviderMetadata.build(configuration: configuration) }

    before do
      allow(configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(metadata)
    end

    it 'is valid when left untampered' do
      subject = described_class.new(raw_xml, configuration: configuration)
      expect(subject).to be_valid
    end

    it 'is invalid if the document has been tampered with' do
      raw_xml.gsub!(issuer, 'corrupt')
      subject = described_class.new(raw_xml)
      expect(subject).to be_invalid
    end

    it 'is invalid when blank' do
      subject = described_class.new('')
      expect(subject).to be_invalid
      expect(subject.errors[:content]).to be_present
    end

    it 'is invalid when not an AuthnRequest' do
      xml = Saml::Kit::IdentityProviderMetadata.build.to_xml
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(metadata).to receive(:matches?).and_return(false)
      subject = described_class.build do |builder|
        builder.issuer = issuer
        builder.assertion_consumer_service_url = assertion_consumer_service_url
      end

      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'is invalid when the service provider is not known' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = described_class.build
      expect(subject).to be_invalid
      expect(subject.errors[:provider]).to be_present
    end

    it 'validates the schema of the request' do
      id = Xml::Kit::Id.generate
      key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
      signed_xml = ::Xml::Kit::Signatures.sign(key_pair: key_pair) do |xml, signature|
        xml.tag!('samlp:AuthnRequest', 'xmlns:samlp' => Saml::Kit::Namespaces::PROTOCOL, AssertionConsumerServiceURL: assertion_consumer_service_url, ID: id) do
          signature.template(id)
          xml.Fake do
            xml.NotAllowed 'Huh?'
          end
        end
      end
      expect(described_class.new(signed_xml)).to be_invalid
    end

    it 'validates a request without a signature' do
      now = Time.now.utc
      raw_xml = <<-XML
<samlp:AuthnRequest AssertionConsumerServiceURL='#{assertion_consumer_service_url}' ID='#{Xml::Kit::Id.generate}' IssueInstant='#{now.iso8601}' Version='2.0' xmlns:saml='#{Saml::Kit::Namespaces::ASSERTION}' xmlns:samlp='#{Saml::Kit::Namespaces::PROTOCOL}'>
  <saml:Issuer>#{issuer}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate='true' Format='#{Saml::Kit::Namespaces::EMAIL_ADDRESS}'/>
</samlp:AuthnRequest>
      XML

      subject = described_class.new(raw_xml, configuration: configuration)
      subject.signature_verified!
      expect(subject).to be_valid
    end

    it 'is valid when there is no signature, and the issuer is registered' do
      now = Time.now.utc
      raw_xml = <<-XML
<samlp:AuthnRequest AssertionConsumerServiceURL='#{assertion_consumer_service_url}' ID='#{Xml::Kit::Id.generate}' IssueInstant='#{now.iso8601}' Version='2.0' xmlns:saml='#{Saml::Kit::Namespaces::ASSERTION}' xmlns:samlp='#{Saml::Kit::Namespaces::PROTOCOL}'>
  <saml:Issuer>#{issuer}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate='true' Format='#{Saml::Kit::Namespaces::PERSISTENT}'/>
</samlp:AuthnRequest>
      XML

      allow(registry).to receive(:metadata_for).with(issuer).and_return(metadata)
      subject = described_class.new(raw_xml, configuration: configuration)
      expect(subject).to be_valid
    end

    it 'is invalid when there is no signature, and the issuer is not registered' do
      now = Time.now.utc
      raw_xml = <<-XML
<samlp:AuthnRequest AssertionConsumerServiceURL='#{assertion_consumer_service_url}' ID='#{Xml::Kit::Id.generate}' IssueInstant='#{now.iso8601}' Version='2.0' xmlns:saml='#{Saml::Kit::Namespaces::ASSERTION}' xmlns:samlp='#{Saml::Kit::Namespaces::PROTOCOL}'>
  <saml:Issuer>#{issuer}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate='true' Format='#{Saml::Kit::Namespaces::PERSISTENT}'/>
</samlp:AuthnRequest>
      XML

      allow(registry).to receive(:metadata_for).with(issuer).and_return(nil)
      subject = described_class.new(raw_xml, configuration: configuration)
      expect(subject).to be_invalid
    end

    context 'when the certificate is expired' do
      let(:expired_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.public_key = private_key.public_key
        certificate.not_before = 1.day.ago
        certificate.not_after = 1.second.ago
        certificate
      end
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:digest_algorithm) { OpenSSL::Digest::SHA256.new }

      before do
        expired_certificate.sign(private_key, digest_algorithm)
      end

      it 'is invalid' do
        document = described_class.build do |x|
          x.embed_signature = true
          certificate = ::Xml::Kit::Certificate.new(expired_certificate)
          x.sign_with(certificate.to_key_pair(private_key))
        end
        subject = described_class.new(document.to_xml)
        expect(subject).to be_invalid
        expect(subject.errors[:certificate]).to be_present
      end
    end
  end

  describe '#assertion_consumer_service_url' do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    it 'returns the ACS in the request' do
      subject = described_class.build do |builder|
        builder.assertion_consumer_service_url = assertion_consumer_service_url
      end
      expect(subject.assertion_consumer_service_url).to eql(assertion_consumer_service_url)
    end

    it 'returns nil' do
      subject = described_class.build do |builder|
        builder.assertion_consumer_service_url = nil
      end

      expect(subject.assertion_consumer_service_url).to be_nil
    end
  end

  describe '.build' do
    let(:url) { FFaker::Internet.uri('https') }
    let(:entity_id) { FFaker::Internet.uri('https') }

    it 'provides a nice API for building metadata' do
      result = described_class.build do |builder|
        builder.issuer = entity_id
        builder.assertion_consumer_service_url = url
      end

      expect(result).to be_instance_of(described_class)
      expect(result.issuer).to eql(entity_id)
      expect(result.assertion_consumer_service_url).to eql(url)
    end
  end

  describe '#response_for' do
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: []) }
    let(:provider) do
      Saml::Kit::ServiceProviderMetadata.build do |x|
        x.add_assertion_consumer_service(FFaker::Internet.uri('https'), binding: :http_post)
      end
    end

    it 'serializes a response' do
      allow(subject).to receive(:provider).and_return(provider)
      url, saml_params = subject.response_for(user, binding: :http_post, relay_state: FFaker::Movie.title)

      response = provider.assertion_consumer_service_for(binding: :http_post).deserialize(saml_params)
      expect(response).to be_instance_of(Saml::Kit::Response)
    end

    it 'serializes a response with the specified signing certificate' do
      allow(subject).to receive(:provider).and_return(provider)
      configuration = Saml::Kit::Configuration.new do |config|
        config.generate_key_pair_for(use: :signing)
      end
      key_pair = configuration.key_pairs(use: :signing).first
      url, saml_params = subject.response_for(user, binding: :http_post, configuration: configuration) do |builder|
        builder.sign_with(key_pair)
      end

      response = provider.assertion_consumer_service_for(binding: :http_post).deserialize(saml_params)
      expect(response).to be_instance_of(Saml::Kit::Response)
    end
  end

  describe '#signature.valid?' do
    it 'returns true when the signature is valid' do
      expect(subject.signature).to be_valid
    end

    it 'returns false when the signature does not match' do
      raw_xml.gsub!(issuer, 'corrupt')
      subject = described_class.new(raw_xml, configuration: configuration)
      expect(subject.signature).not_to be_valid
    end
  end
end
