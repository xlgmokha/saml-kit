require 'spec_helper'

RSpec.describe Saml::Kit::CompositeMetadata do
  subject { described_class.new(xml) }
  let(:post_binding) { Saml::Kit::Bindings::HTTP_POST  }
  let(:redirect_binding) { Saml::Kit::Bindings::HTTP_REDIRECT }
  let(:sign_on_service) { FFaker::Internet.uri("https") }
  let(:xml) do
    <<-XML
<EntityDescriptor xmlns="#{Saml::Kit::Namespaces::METADATA}" ID="#{Saml::Kit::Id.generate}" entityID="#{FFaker::Internet.uri("https")}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
    <SingleLogoutService Binding="#{post_binding}" Location="#{FFaker::Internet.uri("https")}"/>
    <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
    <AssertionConsumerService Binding="#{post_binding}" Location="#{FFaker::Internet.uri("https")}" index="0" isDefault="true"/>
  </SPSSODescriptor>
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
    <SingleLogoutService Binding="#{post_binding}" Location="#{FFaker::Internet.uri("https")}"/>
    <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
    <SingleSignOnService Binding="#{post_binding}" Location="#{sign_on_service}"/>
    <SingleSignOnService Binding="#{redirect_binding}" Location="#{sign_on_service}"/>
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

  describe "#single_sign_on_services" do
    it 'returns the single sign on services from the idp' do
      expect(subject.single_sign_on_services).to match_array([
        Saml::Kit::Bindings::HttpPost.new(location: sign_on_service),
        Saml::Kit::Bindings::HttpRedirect.new(location: sign_on_service),
      ])
    end
  end
end
