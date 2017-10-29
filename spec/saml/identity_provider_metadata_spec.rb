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
    it { expect(subject.name_id_formats).to include("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") }
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
          value: Base64.decode64(certificate),
          fingerprint: "9F:74:13:3B:BC:5A:7B:8B:2D:4F:8B:EF:1E:88:EB:D1:AE:BC:19:BF:CA:19:C6:2F:0F:4B:31:1D:68:98:B0:1B",
        }
      ])
    end
    it { expect(subject.attributes).to be_empty }
  end

  context "active directory metadata" do
    let(:raw_metadata) { IO.read("spec/fixtures/metadata/ad_with_logout.xml") }
    let(:signing_certificate) do
      <<-EOS
MIIC9DCCAdygAwIBAgIQPUYupdctSKhFxrjyD5572DANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDEytBREZTIFNpZ25pbmcgLSBXSU4tOE5QU
EcwME5BQlIuMms4c3NvLmxvY2FsMB4XDTE2MTAwNjIwMzUyMFoXDTE3MTAwNjIwMzUyMFowNjE0MDIGA1UEAxMrQURGUyBTaWduaW5nIC0gV0lOLThOUFBHMDBOQUJSLjJrOHNzb
y5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKBy5neD7sTZ1LJ4ah5tBOYYXvLaTslgyCizqx7vRBsBi9Se+a2Wvo/0KuLe2LtTo4TGA9j0j/1fS4Je3zGDE
3DJn4eodRH34XRIerHuTB8EzjarTE6uxWzpaLhnrzbfFi/BDVX7flf3YDavtmqWJGaKcI155zVl9+Iyp7YOXLpmZumsrVi5L8Xcb79C99T/ErMKS7tXLvBvPslKABqm7+09Btdu/
JCpKpEL+dxKaGj2VRjz1nFgXZPZJ+37nPkThjt3IvAitYzQCIme926AXBoMnS09yG5QN9Y+i8Fk+2YbSkxQTf+6xnxk51NytIzF8VRumNjZu2moOp5THp+Um2UCAwEAATANBgkqh
kiG9w0BAQsFAAOCAQEADzxFG5vtFjnz8SBicenB11wODN6+MP3p+WZGy69eJcig/mq8C4OnOSY9CnQNVhEVgEL8RRmx9TQ3CWrX4QACCQOS9RDlULdczGNnN3hqkj4m/AtyFisbT
1f0U+fBK1W3rEo1IqL0b189O7dPDFDr4lmZq7rc9IkbkPEoIR+saC9krUkEf7wBL0pA7hB591Hk5pxx58L4V5qYADoPinOfHM7/7A2N3TC+L21HerIDSzIHdVNb5dQp0BwU+E7A/
6DqRtw74SyjPVIoPC/2HDwwhuDmV0/ve5ADSl9yYh06hdOrGg0khlP65N38BbZGYMRaul/EeIZTYNbzSVfBNORtaQ==
EOS
    end
    let(:encryption_certificate) do
      <<-EOS
MIIC+jCCAeKgAwIBAgIQHjTznGekMIhCsGKTYQfDSjANBgkqhkiG9w0BAQsFADA5MTcwNQYDVQQDEy5BREZTIEVuY3J5cHRpb24gLSBXSU4tO
E5QUEcwME5BQlIuMms4c3NvLmxvY2FsMB4XDTE2MTAwNjIwMzUyMVoXDTE3MTAwNjIwMzUyMVowOTE3MDUGA1UEAxMuQURGUyBFbmNyeXB0aW9uIC0gV0lOLThOUFBHMDBOQUJSL
jJrOHNzby5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKx9AQ55jyNebZ/n5/WRx8FTQHtEOUUFfoaO6MogC79rsDBdnFrQZh718vTFIV69kRNI9olBlIShc
q9OJ2ZIyA1l1o4aBE5VqUpDq+ReNnlsRmwRStGrwibmfPTQQmwcrO6EqjdIcANYHpOpcsqrP7+s7k1kKGE73nZCCzjlcA63xTJHhC1VmxogHnWOutXYVr1KHwGuWZIF6ElfoGorO
maVq7IOrkAwtwHZXwGz7iD9AWiCZF9c9U+aroPCp0enUgZ4XFk59muYl8GReiRIL/D2Lk/WB6Bz5/5qyJlCcB+BJPMYCfLmllyzN17S2L6kCGEpqL9BhAXf5ZAJDTN1wJsCAwEAA
TANBgkqhkiG9w0BAQsFAAOCAQEAD2frFw+c35baIX1b1daIU+9+o03pzJSLnCdMK0Fy/HAsHQGP8muKGCXdfFCy/cVZ8NxCXX9TsvtiXHyfasQ+H+RJVrer5zRhsQUn1mxP6vNGs
hpY6cJqkXy1jrZA+af53P3ntUi4Ygu1ofzmleULHmK8m6zAGms1GT6ae82OoAfo7YOYwK5/QWWvOla4uF06fw8mfMRkKFEn/CFU1LAxaJ39tO+8/01VQe+bQaBGH7dmLhfkeMsi+
oo3t+uQYdPuPP+WhpsVSEFqgMuzeoo2ZVbfvJUuQNiKvEx97VRe1CAhDasTIlkmN4Fj2Dxkia7nC1esYZd7YQ2LoeDGjyO7oA==
EOS
    end

    it { expect(subject.entity_id).to eql("https://win2008r2-ad-sso.qa1.immunet.com/adfs/services/trust") }
    it { expect(subject.name_id_formats).to include("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") }
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
        { use: 'signing', value: Base64.decode64(signing_certificate), fingerprint: "E6:03:E1:2D:F2:70:9C:D6:CC:8B:3E:4C:5A:37:F5:53:D7:B2:78:B1:2E:95:5B:31:5C:56:E8:7F:16:A1:1B:D2"  },
        { use: 'encryption', value: Base64.decode64(encryption_certificate), fingerprint: "E1:0A:68:23:E4:17:32:A3:3A:F8:B7:30:A3:1D:D8:75:F4:C5:76:48:A4:C0:C8:D3:5E:F1:AE:AB:5B:B2:37:22" },
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
    let(:signing_certificate) do
<<-EOS
MIIC/DCCAeSgAwIBAgIQGobBMVmYz61AqNR/42A7NDANBgkqhkiG9w0BAQsFADA6MTgwNgYDVQQDEy9BREZTIFNpZ25pbmcgLSB3aW4yMDEyc
jItYWQtc3NvLnFhMS5pbW11bmV0LmNvbTAeFw0xNjEwMjExNDUwMDRaFw0xNzEwMjExNDUwMDRaMDoxODA2BgNVBAMTL0FERlMgU2lnbmluZyAtIHdpbjIwMTJyMi1hZC1zc28uc
WExLmltbXVuZXQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuvYden1ksmpxGGvnZGotnRwFCTOYknY4Ol0utUIYTYs/MTOZQtilSRWnsCFhPzUjXATMTF6kK
uiH7LIow2QkYxv8JFMrc9FIUvxRauYJ/GVmedT9gMF2nh62Evi9DExDTM5xRM3bmircPB3cwg6M1BixcbvQtlRj37IEXEApk5ZAY24jivElnsQWwCIV9tLL9Kv4pBCDvQiZl6Bjk
4ZRulyKolQDd9+S0tXISo+OaxQ6WwXbOFDIekUBgNE6ivXrbPH1+CP+paDAMB6vpj5C+o2c3rP9X53Dk4ig0mjw4mbOqd6p/S1Bs3cpNJb1F8RK9SgSxPIV7SIvI8u2FD+XdwIDA
QABMA0GCSqGSIb3DQEBCwUAA4IBAQAlgP26UQUnC/3V1+ZlpCAWO6727MFNtsT/mue6PVEiydtjPurGF7cA4ljfk6E5QEB2U/Hhc4gh0VsbGTAP0g7m/BXAohaxG9S/1ITSj+8B/
4IjLwQjUdPDuGcWHuRgOK84LMFj+Ial6zQUP1G4K0eQRFOEV3PeQVbyGDWBzxadFapN7k+BdDNJ1DgTDuEmJPmGAjHMM8I/m/G/UGQfCwZcB19pFPqhv+sV21D8BQ038y6j5Z3YX
iIThdJ7LVTbOuN3dTXglgXIy0nPTx9YWGV9bf8hqVLwjYmsBRLH7lUoVxNjRkFeXCnbTrgT7AgG/94VlHtvnhJkCfQ3SMsAjwR3
EOS
    end
    let(:encryption_certificate) do
<<-EOS
MIIDAjCCAeqgAwIBAgIQRra0nUbJhqFBNtFtXXUr4jANBgkqhkiG9w0BAQsFADA9MTswOQYDVQQDEzJBREZTIEVuY3J5cHRpb24gLSB3aW4yM
DEycjItYWQtc3NvLnFhMS5pbW11bmV0LmNvbTAeFw0xNjEwMjExNDUwMDZaFw0xNzEwMjExNDUwMDZaMD0xOzA5BgNVBAMTMkFERlMgRW5jcnlwdGlvbiAtIHdpbjIwMTJyMi1hZ
C1zc28ucWExLmltbXVuZXQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqdQOAO/jAtq6Kbdq87+APchTXGNKKr2H168l7iVu7bH/QEtQJg2a3XD5wXwbwAOsM
HbIzdZfaEqn4coB6O2kvombJHSl1+ZSz5bm1JV79afPdvfcfw1RBN7WXt59di3WCCN2dUD6l9FJWjI61B83BSFPsJIXYewhPJRmFV+nbFAVPjLr5wQXWIXm2e5JSxKwpAU3kNuUO
q57O1IKLXvsqTrb0j+LJyCEs8uum3Ex+K/BAzPn4P8Xq6kRmsHLUCivXyjMHmA1T/4S+HMvTRI08O6zYUYbpNDUztzuxYOjjcDRCyLxbWBJIDv2KVoXG5iGF61CFLhtKaWw8mBPF
7OqpQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBDoG1K4XC/xPU3/0BZ0i6DqjzsRhelFB5U9Ufhen+qdx0IjgHwb06U0mUst53kPuLy/uABGUqBololQmctx+RB9A5+6b6Cm6ZQP
Nnxn2nopJNqT6VKKszsOnaphE6kVSFZUFOXQjezCIbyT22sBSa6lxG4wdun5vKThFh8tUDK1radniEKLrsdISgnVMl7KUYUlEDcy4hUOXR4DJkcbgryBgnP81pAUu01+0rfiLvJg
pZnnhMRNYKrMC9X3jSdoSomh+SRV+Pld1j0QX3WambF38qd3AbQ/TXt8ytzh1NwIKkiRDGshkOwKItSbxEMLE2Qx1W4pal0e9J+An7+3eaB
EOS
    end

    it { expect(subject.entity_id).to eql("http://win2012r2-ad-sso.qa1.immunet.com/adfs/services/trust") }
    it { expect(subject.name_id_formats).to include("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") }
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
        { use: "signing", value: Base64.decode64(signing_certificate), fingerprint: "BE:12:70:84:AD:99:6A:58:28:2A:BC:DA:AB:E8:51:D3:FF:AB:58:30:E0:77:DB:23:57:15:01:B3:86:60:97:80" },
        { use: "encryption", value: Base64.decode64(encryption_certificate), fingerprint: "5C:51:0C:8A:6A:02:24:3C:9E:96:96:18:2E:37:65:8F:CC:EA:51:0E:2C:C5:3F:1D:72:47:11:D0:7B:95:26:1F" },
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
