RSpec.describe Saml::Kit::LogoutRequest do
  subject { described_class.build(user, configuration: configuration) }
  let(:user) { double(:user, name_id_for: name_id) }
  let(:name_id) { SecureRandom.uuid }
  let(:issuer) { FFaker::Internet.uri("https") }
  let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.issuer = issuer
      config.registry = registry
      config.generate_key_pair_for(use: :signing)
    end
  end

  it 'parses the issuer' do
    subject = described_class.build(user, configuration: configuration) do |builder|
      builder.issuer = issuer
    end
    expect(subject.issuer).to eql(issuer)
  end

  it 'parses the issue instant' do
    travel_to 1.second.from_now
    expect(subject.issue_instant).to eql(Time.now.utc)
  end

  it 'parses the version' do
    expect(subject.version).to eql("2.0")
  end

  it 'parses the destination' do
    destination = FFaker::Internet.uri("https")
    subject = described_class.build(user, configuration: configuration) do |builder|
      builder.destination = destination
    end
    expect(subject.destination).to eql(destination)
  end

  it 'parses the name_id' do
    expect(subject.name_id).to eql(name_id)
  end

  describe "#valid?" do
    let(:metadata) do
      Saml::Kit::ServiceProviderMetadata.build(configuration: configuration) do |builder|
        builder.entity_id = issuer
        builder.add_single_logout_service(FFaker::Internet.uri("https"), binding: :http_post)
      end
    end

    before :each do
      allow(registry).to receive(:metadata_for).and_return(metadata)
    end

    it 'is valid when left untampered' do
      expect(subject).to be_valid
    end

    it 'is invalid if the document has been tampered with' do
      issuer = FFaker::Internet.uri("https")
      raw_xml = described_class.build(user, configuration: configuration) do |builder|
        builder.issuer = issuer
      end.to_xml.gsub(issuer, 'corrupt')

      expect(described_class.new(raw_xml)).to be_invalid
    end

    it 'is invalid when blank' do
      subject = described_class.new('')
      expect(subject).to be_invalid
      expect(subject.errors[:content]).to be_present
    end

    it 'is invalid when not a LogoutRequest' do
      subject = described_class.new(Saml::Kit::IdentityProviderMetadata.build.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(metadata).to receive(:matches?).and_return(false)
      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'is invalid when the provider is not known' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      expect(subject).to be_invalid
      expect(subject.errors[:provider]).to be_present
    end

    it 'is invalid when single logout service url is not provided' do
      allow(metadata).to receive(:matches?).and_return(true)
      allow(metadata).to receive(:single_logout_services).and_return([])

      expect(subject).to be_invalid
      expect(subject.errors[:single_logout_service]).to be_present
    end

    it 'is valid when a single logout service url is available via the registry' do
      issuer = FFaker::Internet.uri("https")
      allow(registry).to receive(:metadata_for).with(issuer).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      allow(metadata).to receive(:single_logout_services).and_return([
        Saml::Kit::Bindings::HttpPost.new(location: FFaker::Internet.uri("https"))
      ])

      subject = described_class.build(user, configuration: configuration) do |builder|
        builder.issuer = issuer
      end
      expect(subject).to be_valid
    end

    it 'validates the schema of the request' do
      id = Xml::Kit::Id.generate
      configuration = Saml::Kit::Configuration.new
      configuration.generate_key_pair_for(use: :signing)
      signed_xml = Saml::Kit::Signatures.sign(configuration: configuration) do |xml, signature|
        xml.LogoutRequest ID: id do
          signature.template(id)
          xml.Fake do
            xml.NotAllowed "Huh?"
          end
        end
      end
      expect(described_class.new(signed_xml)).to be_invalid
    end
  end

  describe "#response_for" do
    let(:provider) do
      Saml::Kit::IdentityProviderMetadata.build do |builder|
        builder.add_single_logout_service(FFaker::Internet.uri("https"), binding: :http_post)
      end
    end

    it 'serializes a logout response for a particular user' do
      allow(subject).to receive(:provider).and_return(provider)

      _, saml_params = subject.response_for(binding: :http_post)
      response_binding = provider.single_logout_service_for(binding: :http_post)
      result = response_binding.deserialize(saml_params)
      expect(result).to be_instance_of(Saml::Kit::LogoutResponse)
    end
  end
end
