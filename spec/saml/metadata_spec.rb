RSpec.describe Saml::Kit::Metadata do
  describe ".from" do
    subject { described_class }

    it 'returns an identity provider metadata' do
      xml = Saml::Kit::IdentityProviderMetadata.build.to_xml
      expect(subject.from(xml)).to be_instance_of(Saml::Kit::IdentityProviderMetadata)
    end

    it 'returns a service provider metadata' do
      xml = Saml::Kit::ServiceProviderMetadata.build.to_xml
      expect(subject.from(xml)).to be_instance_of(Saml::Kit::ServiceProviderMetadata)
    end

    it 'returns a composite' do
      xml = <<-XML
<EntityDescriptor xmlns="#{Saml::Kit::Namespaces::METADATA}" ID="#{Xml::Kit::Id.generate}" entityID="#{FFaker::Internet.uri("https")}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
    <SingleLogoutService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri("https")}"/>
    <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
    <AssertionConsumerService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri("https")}" index="0" isDefault="true"/>
  </SPSSODescriptor>
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
    <SingleLogoutService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri("https")}"/>
    <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
    <SingleSignOnService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri("https")}"/>
    <SingleSignOnService Binding="#{Saml::Kit::Bindings::HTTP_REDIRECT}" Location="#{FFaker::Internet.uri("https")}"/>
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
      result = subject.from(xml)
      expect(result).to be_present

      expect(result.single_sign_on_services.count).to eql(2)
      expect(result.assertion_consumer_services.count).to eql(1)
      expect(result.single_logout_services.count).to eql(2)
      expect(result.organization_name).to eql("Acme, Inc")
      expect(result.organization_url).to eql("http://localhost:5000/")
      expect(result.contact_person_company).to eql("mailto:hi@example.com")
    end
  end
end
