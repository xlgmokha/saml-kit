require 'spec_helper'

RSpec.describe Saml::Kit::IdentityProviderMetadata do
  describe described_class::Builder do
    subject { described_class.new }
    let(:email) { FFaker::Internet.email }
    let(:org_name) { FFaker::Movie.title }
    let(:url) { "https://#{FFaker::Internet.domain_name}" }
    let(:entity_id) { FFaker::Movie.title }

    it 'builds a proper metadata' do
      subject.contact_email = email
      subject.entity_id = entity_id
      subject.organization_name = org_name
      subject.organization_url = url
      subject.single_sign_on_location = "https://www.example.com/login"
      subject.single_logout_location = "https://www.example.com/logout"
      subject.attributes << "id"

      result = Hash.from_xml(subject.build.to_xml)

      expect(result['EntityDescriptor']['ID']).to be_present
      expect(result['EntityDescriptor']['entityID']).to eql(entity_id)
      expect(result['EntityDescriptor']['IDPSSODescriptor']['protocolSupportEnumeration']).to eql('urn:oasis:names:tc:SAML:2.0:protocol')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['NameIDFormat']).to eql('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleSignOnService']['Binding']).to eql('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleSignOnService']['Location']).to eql("https://www.example.com/login")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleLogoutService']['Binding']).to eql('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleLogoutService']['Location']).to eql("https://www.example.com/logout")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['Name']).to eql("id")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['FriendlyName']).to eql("id")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['NameFormat']).to eql("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")

      expect(result['EntityDescriptor']['Organization']['OrganizationName']).to eql(org_name)
      expect(result['EntityDescriptor']['Organization']['OrganizationDisplayName']).to eql(org_name)
      expect(result['EntityDescriptor']['Organization']['OrganizationURL']).to eql(url)
      expect(result['EntityDescriptor']['ContactPerson']['contactType']).to eql("technical")
      expect(result['EntityDescriptor']['ContactPerson']['Company']).to eql("mailto:#{email}")
    end
  end

  subject { described_class.new(raw_metadata) }

  context "okta metadata" do
    let(:raw_metadata) { IO.read("spec/fixtures/metadata/okta.xml") }
    let(:certificate) do
      Hash.from_xml(raw_metadata)['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor']['KeyInfo']['X509Data']['X509Certificate']
    end

    it { expect(subject.entity_id).to eql("http://www.okta.com/exk8dx3jilpueVzpU0h7") }
    it do
      expect(subject.name_id_formats).to match_array([
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
      ])
    end
    it do
      expect(subject.single_sign_on_services).to match_array([
        { binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", location: "https://dev-989848.oktapreview.com/app/ciscodev843126_portal_1/exk8dx3jilpueVzpU0h7/sso/saml" },
        { binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", location: "https://dev-989848.oktapreview.com/app/ciscodev843126_portal_1/exk8dx3jilpueVzpU0h7/sso/saml" },
      ])
    end
    it { expect(subject.single_logout_services).to be_empty }
    it do
      expect(subject.certificates).to match_array([
        {
          use: "signing",
          text: certificate,
          fingerprint: "9F:74:13:3B:BC:5A:7B:8B:2D:4F:8B:EF:1E:88:EB:D1:AE:BC:19:BF:CA:19:C6:2F:0F:4B:31:1D:68:98:B0:1B",
        }
      ])
    end
    it { expect(subject.attributes).to be_empty }
  end

  context "active directory metadata" do
    let(:raw_metadata) { IO.read("spec/fixtures/metadata/ad_with_logout.xml") }
    let(:xml_hash) { Hash.from_xml(raw_metadata) }
    let(:signing_certificate) do
      xml_hash['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].find { |x| x['use'] == 'signing' }['KeyInfo']['X509Data']['X509Certificate']
    end
    let(:encryption_certificate) do
      xml_hash['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].find { |x| x['use'] == 'encryption' }['KeyInfo']['X509Data']['X509Certificate']
    end

    it { expect(subject.entity_id).to eql("https://win2008r2-ad-sso.qa1.immunet.com/adfs/services/trust") }
    it do
      expect(subject.name_id_formats).to match_array([
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      ])
    end
    it do
      expect(subject.single_sign_on_services).to match_array([
        { binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", location: "https://win2008r2-ad-sso.qa1.immunet.com/adfs/ls/" },
        { binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", location: "https://win2008r2-ad-sso.qa1.immunet.com/adfs/ls/" },
      ])
    end
    it do
      expect(subject.single_logout_services).to match_array([
        { location: "https://win2008r2-ad-sso.qa1.immunet.com/adfs/ls/", binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" },
        { location: "https://win2008r2-ad-sso.qa1.immunet.com/adfs/ls/", binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" },
      ])
    end
    it do
      expect(subject.certificates).to match_array([
        {
          text: signing_certificate,
          fingerprint: "E6:03:E1:2D:F2:70:9C:D6:CC:8B:3E:4C:5A:37:F5:53:D7:B2:78:B1:2E:95:5B:31:5C:56:E8:7F:16:A1:1B:D2",
          use: 'signing',
        },
        {
          text: encryption_certificate,
          fingerprint: "E1:0A:68:23:E4:17:32:A3:3A:F8:B7:30:A3:1D:D8:75:F4:C5:76:48:A4:C0:C8:D3:5E:F1:AE:AB:5B:B2:37:22",
          use: 'encryption',
        },
      ])
    end
    it do
      expect(subject.attributes).to include({
        format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        friendly_name: "E-Mail Address",
        name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      })
    end
  end

  context "active directory windows server 2012 metadata" do
    let(:raw_metadata) { IO.read("spec/fixtures/metadata/ad_2012.xml") }
    let(:xml_hash) { Hash.from_xml(raw_metadata) }
    let(:signing_certificate) do
      xml_hash['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].find { |x| x['use'] == 'signing' }['KeyInfo']['X509Data']['X509Certificate']
    end
    let(:encryption_certificate) do
      xml_hash['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].find { |x| x['use'] == 'encryption' }['KeyInfo']['X509Data']['X509Certificate']
    end

    it { expect(subject.entity_id).to eql("http://win2012r2-ad-sso.qa1.immunet.com/adfs/services/trust") }
    it do
      expect(subject.name_id_formats).to match_array([
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      ])
    end
    it do
      expect(subject.single_sign_on_services).to match_array([
        { location: "https://win2012r2-ad-sso.qa1.immunet.com/adfs/ls/", binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" },
        { location: "https://win2012r2-ad-sso.qa1.immunet.com/adfs/ls/", binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" },
      ])
    end
    it do
      expect(subject.single_logout_services).to match_array([
        { location: "https://win2012r2-ad-sso.qa1.immunet.com/adfs/ls/", binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" },
        { location: "https://win2012r2-ad-sso.qa1.immunet.com/adfs/ls/", binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" },
      ])
    end
    it do
      expect(subject.certificates).to match_array([
        { use: "signing", text: signing_certificate, fingerprint: "BE:12:70:84:AD:99:6A:58:28:2A:BC:DA:AB:E8:51:D3:FF:AB:58:30:E0:77:DB:23:57:15:01:B3:86:60:97:80" },
        { use: "encryption", text: encryption_certificate, fingerprint: "5C:51:0C:8A:6A:02:24:3C:9E:96:96:18:2E:37:65:8F:CC:EA:51:0E:2C:C5:3F:1D:72:47:11:D0:7B:95:26:1F" },
      ])
    end
    it { expect(subject.attributes).to be_present }
  end

  describe "#validate" do
    let(:errors) { [] }
    let(:service_provider_metadata) do
      builder = Saml::Kit::ServiceProviderMetadata::Builder.new
      builder.to_xml
    end
    let(:identity_provider_metadata) { IO.read("spec/fixtures/metadata/okta.xml") }

    it 'valid when given valid identity provider metadata' do
      subject = described_class.new(identity_provider_metadata)
      subject.validate do |error|
        errors << error
      end
      expect(errors).to be_empty
    end

    it 'is invalid, when given service provider metadata' do
      subject = described_class.new(service_provider_metadata)
      expect(subject).to_not be_valid
      expect(subject.errors[:metadata]).to include(I18n.translate("saml/kit.errors.identity_provider_metadata.metadata.invalid_idp"))
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
      expect(subject.errors[:metadata][0]).to include("1:0: ERROR: Element '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'")
    end

    context "signature validation" do
      it 'is invalid, when the signature is invalid' do
        old_url = 'https://win2012r2-ad-sso.qa1.immunet.com/adfs/ls/'
        new_url = 'https://myserver.com/hacked'
        metadata_xml = IO.read("spec/fixtures/metadata/ad_2012.xml").gsub(old_url, new_url)

        subject = described_class.new(metadata_xml)
        expect(subject).to be_invalid
        expect(subject.errors[:metadata]).to include("invalid signature.")
      end

      it 'is valid, when the content has not been tampered with' do
        travel_to DateTime.parse('2017-10-21')
        metadata_xml = IO.read("spec/fixtures/metadata/ad_2012.xml")

        subject = described_class.new(metadata_xml)
        expect(subject).to be_valid
      end
    end
  end
end
