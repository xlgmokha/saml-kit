RSpec.describe Saml::Kit::CompositeMetadata do
  subject { described_class.new(xml) }

  let(:post_binding) { Saml::Kit::Bindings::HTTP_POST }
  let(:redirect_binding) { Saml::Kit::Bindings::HTTP_REDIRECT }
  let(:sign_on_service) { FFaker::Internet.uri('https') }
  let(:assertion_consumer_service) { FFaker::Internet.uri('https') }
  let(:sp_logout_service) { FFaker::Internet.uri('https') }
  let(:idp_logout_service) { FFaker::Internet.uri('https') }
  let(:entity_id) { FFaker::Internet.uri('https') }
  let(:sp_signing_certificate) { ::Xml::Kit::KeyPair.generate(use: :signing).certificate }
  let(:sp_encryption_certificate) { ::Xml::Kit::KeyPair.generate(use: :encryption).certificate }
  let(:idp_signing_certificate) { ::Xml::Kit::KeyPair.generate(use: :signing).certificate }
  let(:idp_encryption_certificate) { ::Xml::Kit::KeyPair.generate(use: :encryption).certificate }
  let(:xml) do
    <<-XML.strip_heredoc
      <EntityDescriptor xmlns="#{Saml::Kit::Namespaces::METADATA}" ID="#{::Xml::Kit::Id.generate}" entityID="#{entity_id}">
        <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
          <KeyDescriptor use="signing">
            <KeyInfo xmlns="#{::Xml::Kit::Namespaces::XMLDSIG}">
              <X509Data>
                <X509Certificate>#{sp_signing_certificate.stripped}</X509Certificate>
              </X509Data>
            </KeyInfo>
          </KeyDescriptor>
          <KeyDescriptor use="encryption">
            <KeyInfo xmlns="#{::Xml::Kit::Namespaces::XMLDSIG}">
              <X509Data>
                <X509Certificate>#{sp_encryption_certificate.stripped}</X509Certificate>
              </X509Data>
            </KeyInfo>
          </KeyDescriptor>
          <SingleLogoutService Binding="#{post_binding}" Location="#{sp_logout_service}"/>
          <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
          <AssertionConsumerService Binding="#{post_binding}" Location="#{assertion_consumer_service}" index="0" isDefault="true"/>
        </SPSSODescriptor>
        <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
          <KeyDescriptor use="signing">
            <KeyInfo xmlns="#{::Xml::Kit::Namespaces::XMLDSIG}">
              <X509Data>
                <X509Certificate>#{idp_signing_certificate.stripped}</X509Certificate>
              </X509Data>
            </KeyInfo>
          </KeyDescriptor>
          <KeyDescriptor use="encryption">
            <KeyInfo xmlns="#{::Xml::Kit::Namespaces::XMLDSIG}">
              <X509Data>
                <X509Certificate>#{idp_encryption_certificate.stripped}</X509Certificate>
              </X509Data>
            </KeyInfo>
          </KeyDescriptor>
          <SingleLogoutService Binding="#{post_binding}" Location="#{idp_logout_service}"/>
          <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
          <SingleSignOnService Binding="#{post_binding}" Location="#{sign_on_service}"/>
          <SingleSignOnService Binding="#{redirect_binding}" Location="#{sign_on_service}"/>
          <Attribute xmlns="#{Saml::Kit::Namespaces::ASSERTION}" Name="id" ></Attribute>
        </IDPSSODescriptor>
        <Organization>
          <OrganizationName xml:lang="en">Acme, Inc</OrganizationName>
          <OrganizationDisplayName xml:lang="en">Acme, Inc</OrganizationDisplayName>
          <OrganizationURL xml:lang="en">http://localhost:5000/</OrganizationURL>
        </Organization>
        <ContactPerson contactType="technical">
          <Company>mailto:hi@example.com</Company>
        </ContactPerson>
      </EntityDescriptor>
    XML
  end

  describe '#single_sign_on_services' do
    it 'returns the single sign on services from the idp' do
      expect(subject.single_sign_on_services).to match_array([
        Saml::Kit::Bindings::HttpPost.new(location: sign_on_service),
        Saml::Kit::Bindings::HttpRedirect.new(location: sign_on_service),
      ])
    end
  end

  describe '#single_sign_on_service_for' do
    it 'returns the post binding' do
      expect(subject.single_sign_on_service_for(binding: :http_post)).to eql(
        Saml::Kit::Bindings::HttpPost.new(location: sign_on_service)
      )
    end
  end

  it { expect(subject.want_authn_requests_signed).to be_truthy }
  it { expect(subject.attributes).to match_array([name: 'id', format: nil]) }
  it { expect(subject.login_request_for(binding: :http_post)).to be_present }
  it do
    expect(subject.assertion_consumer_services).to match_array([
      Saml::Kit::Bindings::HttpPost.new(location: assertion_consumer_service)
    ])
  end
  it do
    expect(subject.assertion_consumer_service_for(binding: :http_post)).to eql(
      Saml::Kit::Bindings::HttpPost.new(location: assertion_consumer_service)
    )
  end
  it { expect(subject.want_assertions_signed).to be_truthy }
  it { expect(subject.entity_id).to eql(entity_id) }
  it { expect(subject.name_id_formats).to match_array([Saml::Kit::Namespaces::PERSISTENT]) }
  it do
    expect(subject.certificates).to match_array([
      sp_signing_certificate,
      sp_encryption_certificate,
      idp_signing_certificate,
      idp_encryption_certificate,
    ])
  end

  it do
    expect(subject.encryption_certificates).to match_array([
      sp_encryption_certificate,
      idp_encryption_certificate,
    ])
  end
  it do
    expect(subject.signing_certificates).to match_array([
      sp_signing_certificate,
      idp_signing_certificate,
    ])
  end
  it do
    expect(subject.services('SingleLogoutService')).to match_array([
      Saml::Kit::Bindings::HttpPost.new(location: sp_logout_service),
      Saml::Kit::Bindings::HttpPost.new(location: idp_logout_service),
    ])
  end
  it do
    expect(subject.service_for(type: 'SingleLogoutService', binding: :http_post)).to eql(
      Saml::Kit::Bindings::HttpPost.new(location: sp_logout_service)
    )
  end
  it do
    expect(subject.services('AssertionConsumerService')).to match_array([
      Saml::Kit::Bindings::HttpPost.new(location: assertion_consumer_service),
    ])
  end
  it do
    expect(subject.service_for(type: 'AssertionConsumerService', binding: :http_post)).to eql(
      Saml::Kit::Bindings::HttpPost.new(location: assertion_consumer_service)
    )
  end
  it do
    expect(subject.services('SingleSignOnService')).to match_array([
      Saml::Kit::Bindings::HttpPost.new(location: sign_on_service),
      Saml::Kit::Bindings::HttpRedirect.new(location: sign_on_service),
    ])
  end
  it do
    expect(subject.service_for(type: 'SingleSignOnService', binding: :http_post)).to eql(
      Saml::Kit::Bindings::HttpPost.new(location: sign_on_service)
    )
  end

  it do
    expect(subject.single_logout_services).to match_array([
      Saml::Kit::Bindings::HttpPost.new(location: sp_logout_service),
      Saml::Kit::Bindings::HttpPost.new(location: idp_logout_service),
    ])
  end

  it do
    expect(subject.single_logout_service_for(binding: :http_post)).to eql(
      Saml::Kit::Bindings::HttpPost.new(location: sp_logout_service)
    )
  end

  specify { expect(subject.logout_request_for(User.new)).to be_present }
end
