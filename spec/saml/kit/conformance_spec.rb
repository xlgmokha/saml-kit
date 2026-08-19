# frozen_string_literal: true

# Conformance coverage for the SAML 2.0 Web Browser SSO profile checks added
# in 1.6.0.
#
# Every check gets the same treatment: the 1.6.0 default accepts the document,
# the flag rejects it, and a conformant document passes either way. The
# "accepted by default" examples are the backwards compatibility promise -- if
# one of them ever fails, a default is wrong.
#
# Real key pairs, a real registry and real signatures, as in security_spec.rb.
# Where a check needs a document the builder will not produce, the example
# builds unsigned and validates with signature_required off rather than
# tampering with signed xml. That is a supported configuration rather than a
# stub, and it stops a conformance failure hiding behind a signature failure.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Web Browser SSO profile conformance' do
  subject(:response) { Saml::Kit::Response.new(xml, configuration: sp_configuration) }

  let(:namespaces) { Saml::Kit::Document::NAMESPACES }
  let(:as_xml) { Nokogiri::XML::Node::SaveOptions::AS_XML }

  let(:idp_entity_id) { 'https://idp.example.com/metadata' }
  let(:sp_entity_id) { 'https://sp.example.com/metadata' }
  let(:acs_url) { 'https://sp.example.com/acs' }

  let(:idp_configuration) do
    Saml::Kit::Configuration.new do |config|
      config.entity_id = idp_entity_id
      config.generate_key_pair_for(use: :signing)
    end
  end

  let(:idp_metadata_xml) do
    Saml::Kit::IdentityProviderMetadata.build(configuration: idp_configuration) do |x|
      x.entity_id = idp_entity_id
      x.add_single_sign_on_service('https://idp.example.com/login', binding: :http_post)
      x.add_single_logout_service('https://idp.example.com/logout', binding: :http_post)
    end.to_xml
  end

  let(:registry) do
    Saml::Kit::DefaultRegistry.new.tap do |x|
      x.register(Saml::Kit::IdentityProviderMetadata.new(idp_metadata_xml))
    end
  end

  let(:sp_configuration) do
    Saml::Kit::Configuration.new do |config|
      config.entity_id = sp_entity_id
      config.registry = registry
    end
  end

  let(:user) { User.new(attributes: { id: SecureRandom.uuid }) }

  let(:request) do
    instance_double(
      Saml::Kit::AuthenticationRequest,
      id: ::Xml::Kit::Id.generate,
      issuer: sp_entity_id,
      assertion_consumer_service_url: acs_url,
      name_id_format: Saml::Kit::Namespaces::PERSISTENT,
      provider: nil,
      signed?: true,
      trusted?: true
    )
  end

  # Signed, addressed to this service provider, with a bearer confirmation
  # naming the assertion consumer service url.
  let(:conformant_xml) do
    Saml::Kit::Response.build(user, request, configuration: idp_configuration) do |x|
      x.issuer = idp_entity_id
      x.embed_signature = true
      x.destination = acs_url
    end.to_xml
  end

  let(:unsigned_xml) do
    Saml::Kit::Response.build(user, request, configuration: idp_configuration) do |x|
      x.issuer = idp_entity_id
      x.embed_signature = false
      x.destination = acs_url
    end.to_xml
  end

  def audience_in(xml)
    Nokogiri::XML(xml).at_xpath('//saml:Audience', namespaces).try(:text)
  end

  context 'with a conformant response' do
    let(:xml) { conformant_xml }

    it 'is valid with every check enabled and every expectation supplied' do
      sp_configuration.audience_required = true
      sp_configuration.subject_confirmation_required = true
      sp_configuration.authn_statement_required = true
      response.expected_destination = acs_url
      response.expected_recipient = acs_url
      response.request_id = request.id
      expect(response).to be_valid
    end
  end

  describe 'configuration.audience_required' do
    # An unsolicited response. With no request there is no issuer to derive an
    # audience from, which is how saml-kit came to emit audience-less
    # assertions in the first place.
    let(:xml) do
      Saml::Kit::Response.build(user, configuration: idp_configuration) do |x|
        x.issuer = idp_entity_id
        x.embed_signature = true
      end.to_xml
    end

    it 'accepts an assertion with no audience by default' do
      expect(sp_configuration.audience_required).to be(false)
      expect(response).to be_valid
    end

    it 'rejects an assertion with no audience when enabled' do
      sp_configuration.audience_required = true
      expect(response).to be_invalid
      expect(response.errors[:audience]).to include(
        response.assertion.error_message(:must_have_audience)
      )
    end
  end

  describe 'an audience naming a different service provider' do
    let(:xml) do
      Saml::Kit::Response.build(user, request, configuration: idp_configuration) do |x|
        x.issuer = idp_entity_id
        x.embed_signature = true
        x.audience = 'https://other.example.com/metadata'
      end.to_xml
    end

    # must_match_issuer moved out of Assertion into BearerConfirmable to make
    # room under Metrics/ClassLength. This guards the move.
    it 'is rejected whether or not audience_required is set' do
      expect(response).to be_invalid
      expect(response.errors[:audience]).to include(
        response.assertion.error_message(:must_match_issuer)
      )
    end
  end

  describe 'configuration.subject_confirmation_required' do
    shared_examples 'a non conformant confirmation' do
      it 'is accepted by default' do
        expect(sp_configuration.subject_confirmation_required).to be(false)
        expect(response).to be_valid
      end

      it 'is rejected when enabled' do
        sp_configuration.subject_confirmation_required = true
        expect(response).to be_invalid
        expect(response.errors[:assertion]).to include(
          response.assertion.error_message(:missing_subject_confirmation)
        )
      end
    end

    context 'with a structurally defective confirmation' do
      before { sp_configuration.signature_required = false }

      context 'when there is no SubjectConfirmation at all' do
        let(:xml) do
          document = Nokogiri::XML(unsigned_xml)
          document.at_xpath('//saml:SubjectConfirmation', namespaces).remove
          document.to_xml(save_with: as_xml)
        end

        it_behaves_like 'a non conformant confirmation'
      end

      context 'when the Method is not bearer' do
        let(:xml) do
          document = Nokogiri::XML(unsigned_xml)
          document.at_xpath('//saml:SubjectConfirmation', namespaces)['Method'] =
            "#{Saml::Kit::Namespaces::SAML_2_0}:cm:holder-of-key"
          document.to_xml(save_with: as_xml)
        end

        it_behaves_like 'a non conformant confirmation'
      end

      context 'when NotOnOrAfter is absent' do
        let(:xml) do
          document = Nokogiri::XML(unsigned_xml)
          document
            .at_xpath('//saml:SubjectConfirmationData', namespaces)
            .remove_attribute('NotOnOrAfter')
          document.to_xml(save_with: as_xml)
        end

        it_behaves_like 'a non conformant confirmation'
      end

      # Profiles 4.1.4.2 says a bearer SubjectConfirmationData MUST NOT carry
      # a NotBefore. The xsd allows it, so only a profile check catches it.
      context 'when NotBefore is present' do
        let(:xml) do
          document = Nokogiri::XML(unsigned_xml)
          document.at_xpath('//saml:SubjectConfirmationData', namespaces)['NotBefore'] =
            Time.now.utc.iso8601
          document.to_xml(save_with: as_xml)
        end

        it_behaves_like 'a non conformant confirmation'
      end
    end

    # The bearer window is five minutes, far tighter than the three hour
    # Conditions window, so this expires while the assertion is still active.
    context 'when the bearer window has closed' do
      let(:xml) { conformant_xml }

      it 'is accepted by default' do
        xml # build the document before moving the clock
        travel_to 10.minutes.from_now
        expect(response).to be_valid
      end

      it 'is rejected when enabled' do
        xml
        sp_configuration.subject_confirmation_required = true
        travel_to 10.minutes.from_now
        expect(response).to be_invalid
        expect(response.errors[:assertion]).to include(
          response.assertion.error_message(:expired_subject_confirmation)
        )
      end
    end
  end

  describe 'configuration.authn_statement_required' do
    before { sp_configuration.signature_required = false }

    let(:xml) do
      document = Nokogiri::XML(unsigned_xml)
      document.at_xpath('//saml:AuthnStatement', namespaces).remove
      document.to_xml(save_with: as_xml)
    end

    it 'accepts an assertion with no AuthnStatement by default' do
      expect(sp_configuration.authn_statement_required).to be(false)
      expect(response).to be_valid
    end

    it 'rejects an assertion with no AuthnStatement when enabled' do
      sp_configuration.authn_statement_required = true
      expect(response).to be_invalid
      expect(response.errors[:assertion]).to include(
        response.assertion.error_message(:missing_authn_statement)
      )
    end
  end

  describe 'configuration.logout_signature_required' do
    subject(:logout_request) do
      Saml::Kit::LogoutRequest.new(logout_xml, configuration: sp_configuration)
    end

    let(:logout_xml) do
      Saml::Kit::LogoutRequest.build(user, configuration: idp_configuration) do |x|
        x.issuer = idp_entity_id
        x.embed_signature = false
      end.to_xml
    end

    it 'accepts an unsigned LogoutRequest by default' do
      expect(sp_configuration.logout_signature_required).to be(false)
      expect(logout_request).to be_valid
    end

    it 'rejects an unsigned LogoutRequest when enabled' do
      sp_configuration.logout_signature_required = true
      expect(logout_request).to be_invalid
      expect(logout_request.errors[:base]).to include(
        logout_request.error_message(:unsigned)
      )
    end

    # The master switch still wins, so an operator who has turned signatures
    # off entirely does not get logout signatures forced back on.
    it 'defers to signature_required' do
      sp_configuration.logout_signature_required = true
      sp_configuration.signature_required = false
      expect(logout_request).to be_valid
    end
  end

  describe '#expected_destination' do
    let(:xml) { conformant_xml }

    it 'is not checked until the application supplies one' do
      expect(response.destination).to eql(acs_url)
      expect(response).to be_valid
    end

    it 'accepts a Destination that matches' do
      response.expected_destination = acs_url
      expect(response).to be_valid
    end

    it 'accepts spellings that are equivalent by definition' do
      response.expected_destination = 'HTTPS://SP.EXAMPLE.COM:443/acs'
      expect(response).to be_valid
    end

    it 'rejects a Destination naming another endpoint' do
      response.expected_destination = 'https://sp.example.com/other'
      expect(response).to be_invalid
      expect(response.errors[:destination]).to include(
        response.error_message(:invalid_destination)
      )
    end
  end

  describe '#expected_recipient' do
    let(:xml) { conformant_xml }

    it 'is not checked until the application supplies one' do
      expect(response).to be_valid
    end

    it 'accepts a Recipient that matches' do
      response.expected_recipient = acs_url
      expect(response).to be_valid
    end

    it 'rejects a Recipient naming another endpoint' do
      response.expected_recipient = 'https://sp.example.com/other'
      expect(response).to be_invalid
      expect(response.errors[:recipient]).to include(
        response.assertion.error_message(:invalid_recipient)
      )
    end

    it 'reaches an assertion that was already built' do
      response.assertion
      response.expected_recipient = 'https://sp.example.com/other'
      expect(response).to be_invalid
    end
  end

  describe '#request_id' do
    let(:xml) { conformant_xml }

    # request_id was read only before 1.6.0, so a caller deserializing through
    # a binding had no way to switch the InResponseTo check on.
    it 'can be assigned after construction' do
      response.request_id = request.id
      expect(response).to be_valid
    end

    it 'rejects a response answering a different request' do
      response.request_id = ::Xml::Kit::Id.generate
      expect(response).to be_invalid
      expect(response.errors[:in_response_to]).to be_present
    end
  end

  describe 'building a response' do
    it 'derives the audience from the request when there is one' do
      expect(audience_in(conformant_xml)).to eql(sp_entity_id)
    end

    it 'emits an AudienceRestriction for an unsolicited response when told the audience' do
      xml = Saml::Kit::Response.build_xml(user, configuration: idp_configuration) do |x|
        x.issuer = idp_entity_id
        x.audience = sp_entity_id
      end
      expect(audience_in(xml)).to eql(sp_entity_id)
    end

    it 'emits none when it has no audience to name' do
      xml = Saml::Kit::Response.build_xml(user, configuration: idp_configuration) do |x|
        x.issuer = idp_entity_id
      end
      expect(audience_in(xml)).to be_nil
    end
  end
end
# rubocop:enable RSpec/DescribeClass
