require 'spec_helper'

RSpec.describe Saml::Kit::IdentityProviderMetadata do
  subject { described_class.new(raw_metadata) }

  context "okta metadata" do
    let(:raw_metadata) { IO.read("spec/fixtures/metadata/okta.xml") }
    let(:certificate) do
      Hash.from_xml(raw_metadata)['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor']['KeyInfo']['X509Data']['X509Certificate']
    end

    it { expect(subject.entity_id).to eql("http://www.okta.com/1") }
    it { expect(subject.name_id_formats).to match_array([ Saml::Kit::Namespaces::EMAIL_ADDRESS, Saml::Kit::Namespaces::UNSPECIFIED_NAMEID ]) }
    it do
      location = "https://dev.oktapreview.com/app/example/1/sso/saml"
      expect(subject.single_sign_on_services.map(&:to_h)).to match_array([
        { binding: Saml::Kit::Bindings::HTTP_POST, location: location },
        { binding: Saml::Kit::Bindings::HTTP_REDIRECT, location: location },
      ])
    end
    it { expect(subject.single_logout_services).to be_empty }
    it do
      fingerprint = "9F:74:13:3B:BC:5A:7B:8B:2D:4F:8B:EF:1E:88:EB:D1:AE:BC:19:BF:CA:19:C6:2F:0F:4B:31:1D:68:98:B0:1B"
      expect(subject.certificates).to match_array([Saml::Kit::Certificate.new(certificate, use: :signing)])
      expect(subject.certificates.first.fingerprint.to_s).to eql(fingerprint)
    end
    it { expect(subject.attributes).to be_empty }
  end

  context "active directory" do
    let(:raw_metadata) { IO.read("spec/fixtures/metadata/ad_2012.xml") }
    let(:xml_hash) { Hash.from_xml(raw_metadata) }
    let(:signing_certificate) do
      xml_hash['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].find { |x| x['use'] == 'signing' }['KeyInfo']['X509Data']['X509Certificate']
    end
    let(:encryption_certificate) do
      xml_hash['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].find { |x| x['use'] == 'encryption' }['KeyInfo']['X509Data']['X509Certificate']
    end

    it { expect(subject.entity_id).to eql("http://www.example.com/adfs/services/trust") }
    it do
      expect(subject.name_id_formats).to match_array([
        Saml::Kit::Namespaces::EMAIL_ADDRESS,
        Saml::Kit::Namespaces::PERSISTENT,
        Saml::Kit::Namespaces::TRANSIENT,
      ])
    end
    it do
      location = "https://www.example.com/adfs/ls/"
      expect(subject.single_sign_on_services.map(&:to_h)).to match_array([
        { location: location, binding: Saml::Kit::Bindings::HTTP_REDIRECT },
        { location: location, binding: Saml::Kit::Bindings::HTTP_POST },
      ])
    end
    it do
      location = "https://www.example.com/adfs/ls/"
      expect(subject.single_logout_services.map(&:to_h)).to match_array([
        { location: location, binding: Saml::Kit::Bindings::HTTP_REDIRECT },
        { location: location, binding: Saml::Kit::Bindings::HTTP_POST },
      ])
    end
    it do
      expect(subject.certificates).to match_array([
        Saml::Kit::Certificate.new(signing_certificate, use: :signing),
        Saml::Kit::Certificate.new(encryption_certificate, use: :encryption),
      ])
    end
    it { expect(subject.attributes).to be_present }
  end

  describe "#validate" do
    it 'valid when given valid identity provider metadata' do
      subject = described_class.build do |builder|
        builder.attributes = [:email]
        builder.add_single_sign_on_service(FFaker::Internet.http_url, binding: :http_post)
        builder.add_single_sign_on_service(FFaker::Internet.http_url, binding: :http_redirect)
        builder.add_single_logout_service(FFaker::Internet.http_url, binding: :http_post)
        builder.add_single_logout_service(FFaker::Internet.http_url, binding: :http_redirect)
      end
      expect(subject).to be_valid
    end

    it 'is invalid, when given service provider metadata' do
      service_provider_metadata = Saml::Kit::ServiceProviderMetadata.build.to_xml
      subject = described_class.new(service_provider_metadata)
      expect(subject).to_not be_valid
      expect(subject.errors[:base]).to include(I18n.translate("saml/kit.errors.IDPSSODescriptor.invalid"))
    end

    it 'is invalid, when the metadata is nil' do
      subject = described_class.new(nil)
      expect(subject).to_not be_valid
      expect(subject.errors[:metadata]).to include("can't be blank")
    end

    it 'is invalid, when the metadata does not validate against the xsd schema' do
      xml = ::Builder::XmlMarkup.new
      xml.instruct!
      xml.EntityDescriptor 'xmlns': Saml::Kit::Namespaces::METADATA do
        xml.IDPSSODescriptor do
          xml.Fake foo: :bar
        end
      end
      subject = described_class.new(xml.target!)
      expect(subject).to_not be_valid
      expect(subject.errors[:base][0]).to include("1:0: ERROR: Element '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'")
    end

    it 'is invalid, when the signature is invalid' do
      old_url = 'https://www.example.com/adfs/ls/'
      new_url = 'https://myserver.com/hacked'
      metadata_xml = IO.read("spec/fixtures/metadata/ad_2012.xml").gsub(old_url, new_url)

      subject = described_class.new(metadata_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include("invalid signature.")
    end
  end

  describe "#single_sign_on_service_for" do
    let(:post_url) { FFaker::Internet.http_url }
    let(:redirect_url) { FFaker::Internet.http_url }

    subject do
      described_class.build do |builder|
        builder.add_single_sign_on_service(redirect_url, binding: :http_redirect)
        builder.add_single_sign_on_service(post_url, binding: :http_post)
      end
    end

    it 'returns the POST binding' do
      result = subject.single_sign_on_service_for(binding: :http_post)
      expect(result.location).to eql(post_url)
      expect(result.binding).to eql(Saml::Kit::Bindings::HTTP_POST)
    end

    it 'returns the HTTP_REDIRECT binding' do
      result = subject.single_sign_on_service_for(binding: :http_redirect)
      expect(result.location).to eql(redirect_url)
      expect(result.binding).to eql(Saml::Kit::Bindings::HTTP_REDIRECT)
    end

    it 'returns nil if the binding cannot be found' do
      expect(subject.single_sign_on_service_for(binding: :soap)).to be_nil
    end
  end

  describe "#want_authn_requests_signed" do
    it 'returns true when enabled' do
      subject = described_class.build do |builder|
        builder.want_authn_requests_signed = true
      end
      expect(subject.want_authn_requests_signed).to be(true)
    end

    it 'returns false when disabled' do
      subject = described_class.build do |builder|
        builder.want_authn_requests_signed = false
      end
      expect(subject.want_authn_requests_signed).to be(false)
    end

    it 'returns true when the attribute is missing' do
      xml = described_class.build do |builder|
        builder.want_authn_requests_signed = false
      end.to_xml.gsub("WantAuthnRequestsSigned=\"false\"", "")
      subject = described_class.new(xml)
      expect(subject.want_authn_requests_signed).to be(true)
    end
  end

  describe "#single_logout_service_for" do
    let(:redirect_url) { FFaker::Internet.uri("https") }
    let(:post_url) { FFaker::Internet.uri("https") }
    let(:subject) do
      described_class.build do |builder|
        builder.add_single_logout_service(redirect_url, binding: :http_redirect)
        builder.add_single_logout_service(post_url, binding: :http_post)
      end
    end

    it 'returns the location for the matching binding' do
      expect(subject.single_logout_service_for(binding: :http_post).location).to eql(post_url)
      expect(subject.single_logout_service_for(binding: :http_redirect).location).to eql(redirect_url)
    end

    it 'returns nil if the binding is not available' do
      expect(subject.single_logout_service_for(binding: :soap)).to be_nil
    end
  end

  describe ".build" do
    let(:url) { FFaker::Internet.uri("https") }
    let(:entity_id) { FFaker::Internet.uri("https") }

    it 'provides a nice API for building metadata' do
      result = described_class.build do |builder|
        builder.entity_id = entity_id
        builder.add_single_sign_on_service(url, binding: :http_post)
      end

      expect(result).to be_instance_of(described_class)
      expect(result.entity_id).to eql(entity_id)
      expect(result.single_sign_on_service_for(binding: :http_post).location).to eql(url)
    end
  end

  describe "#login_request_for" do
    it 'returns a serialized login request' do
      subject = described_class.build do |x|
        x.add_single_sign_on_service(FFaker::Internet.uri("https"), binding: :http_post)
      end
      url, saml_params = subject.login_request_for(binding: :http_post, relay_state: FFaker::Movie.title)
      result = subject.single_sign_on_service_for(binding: :http_post).deserialize(saml_params)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end
  end
end
