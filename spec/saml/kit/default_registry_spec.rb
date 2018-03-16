# frozen_string_literal: true

RSpec.describe Saml::Kit::DefaultRegistry do
  subject { described_class.new }

  let(:entity_id) { FFaker::Internet.http_url }
  let(:service_provider_metadata) do
    Saml::Kit::ServiceProviderMetadata.build do |builder|
      builder.entity_id = entity_id
      builder.add_assertion_consumer_service(FFaker::Internet.uri('https'), binding: :http_post)
    end
  end
  let(:identity_provider_metadata) do
    Saml::Kit::IdentityProviderMetadata.build do |builder|
      builder.entity_id = entity_id
      builder.add_single_sign_on_service(FFaker::Internet.uri('https'), binding: :http_post)
    end
  end

  describe '#metadata_for' do
    it 'returns the metadata for the entity_id' do
      subject.register(service_provider_metadata)
      expect(subject.metadata_for(entity_id)).to eql(service_provider_metadata)
    end
  end

  describe '#register_url' do
    let(:url) { FFaker::Internet.http_url }

    it 'fetches the SP metadata from a remote url and registers it' do
      stub_request(:get, url)
        .to_return(status: 200, body: service_provider_metadata.to_xml)
      subject.register_url(url)

      result = subject.metadata_for(entity_id)
      expect(result).to be_present
      expect(result).to be_instance_of(Saml::Kit::ServiceProviderMetadata)
    end

    it 'fetches the IDP metadata from a remote url' do
      stub_request(:get, url)
        .to_return(status: 200, body: identity_provider_metadata.to_xml)
      subject.register_url(url)

      result = subject.metadata_for(entity_id)
      expect(result).to be_present
      expect(result).to be_instance_of(Saml::Kit::IdentityProviderMetadata)
    end

    it 'registers metadata that serves as both an IDP and SP' do
      xml = <<-XML.strip_heredoc
        <EntityDescriptor xmlns="#{Saml::Kit::Namespaces::METADATA}" ID="#{::Xml::Kit::Id.generate}" entityID="#{entity_id}">
          <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
            <SingleLogoutService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri('https')}"/>
            <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
            <AssertionConsumerService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri('https')}" index="0" isDefault="true"/>
          </SPSSODescriptor>
          <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="#{Saml::Kit::Namespaces::PROTOCOL}">
            <SingleLogoutService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri('https')}"/>
            <NameIDFormat>#{Saml::Kit::Namespaces::PERSISTENT}</NameIDFormat>
            <SingleSignOnService Binding="#{Saml::Kit::Bindings::HTTP_POST}" Location="#{FFaker::Internet.uri('https')}"/>
            <SingleSignOnService Binding="#{Saml::Kit::Bindings::HTTP_REDIRECT}" Location="#{FFaker::Internet.uri('https')}"/>
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
      stub_request(:get, url).to_return(status: 200, body: xml)
      subject.register_url(url)

      result = subject.metadata_for(entity_id)
      expect(result).to be_present
      expect(result).to be_instance_of(Saml::Kit::CompositeMetadata)
    end
  end

  describe '#register' do
    it 'registers the metadata' do
      metadata = Saml::Kit::IdentityProviderMetadata.build do |xxx|
        xxx.entity_id = FFaker::Internet.uri('https')
        xxx.add_single_sign_on_service(FFaker::Internet.uri('https'), binding: :http_post)
      end
      subject.register(metadata)
      expect(subject.metadata_for(metadata.entity_id)).to eql(metadata)
    end

    it 'raises an error when the metadata is invalid' do
      expect do
        subject.register(Saml::Kit::IdentityProviderMetadata.build)
      end.to raise_error(/Cannot register invalid metadata/)
    end

    it 'raises an error when the document is not a metadata' do
      authn_request = Saml::Kit::AuthenticationRequest.build
      allow(authn_request).to receive(:valid?).and_return(true)

      expect do
        subject.register(authn_request)
      end.to raise_error(/Cannot register invalid metadata/)
    end

    it 'raises an error when the document is nil' do
      expect do
        subject.register(nil)
      end.to raise_error(/Cannot register invalid metadata/)
    end
  end

  describe '#each' do
    it 'yields each registered metadata' do
      idp = Saml::Kit::IdentityProviderMetadata.build do |xxx|
        xxx.entity_id = 'idp'
        xxx.add_single_sign_on_service(FFaker::Internet.uri('https'), binding: :http_post)
      end
      sp = Saml::Kit::ServiceProviderMetadata.build do |xxx|
        xxx.entity_id = 'sp'
        xxx.add_assertion_consumer_service(FFaker::Internet.uri('https'), binding: :http_post)
      end

      subject.register(idp)
      subject.register(sp)

      expect(subject.map(&:to_xml)).to match_array([idp.to_xml, sp.to_xml])
    end
  end
end
