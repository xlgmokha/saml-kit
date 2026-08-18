# frozen_string_literal: true

# Regression coverage for the signature stripping and signature wrapping
# advisories. Each example asserts the behaviour we want, so every example in
# this file fails against a vulnerable build.
#
# Nothing here is stubbed: real key pairs, a real registry, real signatures.
# Stubbing the trust path would defeat the purpose.
# This file spans Response, Assertion, Signature and Trustable, so there is no
# single described class.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Signature verification' do
  subject(:response) { Saml::Kit::Response.new(xml, configuration: sp_configuration) }

  let(:namespaces) { Saml::Kit::Document::NAMESPACES }
  let(:as_xml) { Nokogiri::XML::Node::SaveOptions::AS_XML }

  let(:idp_entity_id) { 'https://idp.example.com/metadata' }
  let(:sp_entity_id) { 'https://sp.example.com/metadata' }

  let(:idp_configuration) do
    Saml::Kit::Configuration.new do |config|
      config.entity_id = idp_entity_id
      config.generate_key_pair_for(use: :signing)
    end
  end

  let(:registry) do
    Saml::Kit::DefaultRegistry.new.tap do |x|
      x.register(Saml::Kit::IdentityProviderMetadata.new(idp_metadata_xml))
    end
  end

  let(:idp_metadata_xml) do
    Saml::Kit::IdentityProviderMetadata.build(configuration: idp_configuration) do |x|
      x.entity_id = idp_entity_id
      x.add_single_sign_on_service('https://idp.example.com/login', binding: :http_post)
    end.to_xml
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
      assertion_consumer_service_url: "#{sp_entity_id}/acs",
      name_id_format: Saml::Kit::Namespaces::PERSISTENT,
      provider: nil,
      signed?: true,
      trusted?: true
    )
  end

  # A Response signed at both the Response and Assertion level.
  let(:signed_xml) do
    Saml::Kit::Response.build(user, request, configuration: idp_configuration) do |x|
      x.issuer = idp_entity_id
      x.embed_signature = true
    end.to_xml
  end

  # A Response signed only at the Response level.
  let(:response_signed_xml) do
    Saml::Kit::Response.build(user, request, configuration: idp_configuration) do |x|
      x.issuer = idp_entity_id
      x.embed_signature = true
      x.assertion.embed_signature = false
    end.to_xml
  end

  def described_response(xml)
    Saml::Kit::Response.new(xml, configuration: sp_configuration)
  end

  shared_examples 'an accepted Response' do
    it 'is valid and reports the real subject' do
      expect(response).to be_valid
      expect(response.name_id).to eql(user.name_id)
    end
  end

  # Rejecting a forgery is only meaningful if the reference check still binds a
  # signature to whichever element the identity provider chose to sign.
  shared_examples 'a rejected forgery' do
    it 'is invalid' do
      expect(response).to be_invalid
    end

    it 'does not report the forged document as trusted' do
      response.valid?
      expect(response).not_to be_trusted
      expect(response.assertion).not_to be_trusted
    end
  end

  context 'when signed at both the Response and Assertion level' do
    let(:xml) { signed_xml }

    it_behaves_like 'an accepted Response'
  end

  context 'when signed only at the Response level' do
    let(:xml) { response_signed_xml }

    it_behaves_like 'an accepted Response'
  end

  # Signing only the Assertion is the default for several identity providers,
  # so requiring a signature must not reject it.
  context 'when signed only at the Assertion level' do
    let(:xml) do
      document = Nokogiri::XML(signed_xml)
      document.at_xpath('/samlp:Response/ds:Signature', namespaces).remove
      document.to_xml(save_with: as_xml)
    end

    it_behaves_like 'an accepted Response'

    # Widening this to include the Assertion's signature would silently relax
    # every `raise unless response.trusted?` guard written against 1.4.1.
    it 'still reports trusted? for the Response element alone' do
      expect(response).not_to be_trusted
      expect(response.assertion).to be_trusted
    end
  end

  # The opt-out exists so an operator whose identity provider signs nothing can
  # stage the upgrade instead of pinning 1.4.1. It restores 1.4.1 behaviour
  # exactly, forgeries included, which is why it defaults to on.
  describe 'configuration.signature_required' do
    let(:xml) do
      document = Nokogiri::XML(signed_xml)
      document.xpath('//ds:Signature', namespaces).each(&:remove)
      document.to_xml(save_with: as_xml)
    end

    it 'defaults to requiring a signature' do
      expect(sp_configuration.signature_required).to be(true)
      expect(response).to be_invalid
    end

    it 'accepts an unsigned Response from a registered issuer when disabled' do
      sp_configuration.signature_required = false
      expect(response).to be_valid
    end

    it 'still refuses to call an unsigned Response trusted when disabled' do
      sp_configuration.signature_required = false
      response.valid?
      expect(response).not_to be_trusted
    end
  end

  describe 'error reporting' do
    let(:xml) { signed_xml }

    # The signature requirement has nothing to say about a document that is not
    # a Response at all, and prepending to :base changes errors[:base].first.
    it 'does not demand a signature from a document with no Response element' do
      document = Saml::Kit::Response.new('', configuration: sp_configuration)
      document.valid?
      expect(document.errors[:base]).not_to include('must be signed.')
    end

    it 'reports a fingerprint mismatch once, not once per element' do
      foreign = Saml::Kit::Configuration.new do |config|
        config.entity_id = idp_entity_id
        config.generate_key_pair_for(use: :signing)
      end
      document = Nokogiri::XML(
        Saml::Kit::Response.build(user, request, configuration: foreign) do |x|
          x.issuer = idp_entity_id
          x.embed_signature = true
        end.to_xml
      )
      document.at_xpath('/samlp:Response/ds:Signature', namespaces).remove
      response = described_response(document.to_xml(save_with: as_xml))
      response.valid?
      expect(response.errors[:fingerprint].count).to be(1)
    end
  end

  describe 'signature stripping' do
    let(:xml) do
      document = Nokogiri::XML(signed_xml)
      document.xpath('//ds:Signature', namespaces).each(&:remove)
      document.at_xpath('//saml:NameID', namespaces).content = 'attacker@evil.com'
      document.to_xml(save_with: as_xml)
    end

    it_behaves_like 'a rejected forgery'

    it 'reports the missing signature' do
      response.valid?
      expect(response.errors[:base]).to include('must be signed.')
    end
  end

  describe 'a bare Assertion delivered as the whole document' do
    subject(:assertion) do
      Saml::Kit::Document.to_saml_document(xml, configuration: sp_configuration)
    end

    let(:bare) do
      Nokogiri::XML(signed_xml)
        .at_xpath('/samlp:Response/saml:Assertion', namespaces)
    end

    context 'when its signature is intact' do
      let(:xml) { bare.to_xml(save_with: as_xml) }

      it 'is accepted' do
        expect(assertion).to be_a(Saml::Kit::Assertion)
        expect(assertion).to be_valid
      end
    end

    context 'when its signature has been stripped' do
      let(:xml) do
        bare.at_xpath('./ds:Signature', namespaces).remove
        bare.at_xpath('.//saml:NameID', namespaces).content = 'attacker@evil.com'
        bare.to_xml(save_with: as_xml)
      end

      it 'is invalid' do
        expect(assertion).to be_invalid
      end

      # A missing locale key would surface here as "Translation missing".
      it 'reports the missing signature' do
        assertion.valid?
        expect(assertion.errors[:base]).to include('must be signed.')
      end
    end
  end

  describe 'signature wrapping' do
    context 'when the original assertion is hidden in saml:Advice' do
      let(:xml) do
        document = Nokogiri::XML(signed_xml)
        document.at_xpath('/samlp:Response/ds:Signature', namespaces).remove
        original = document.at_xpath('/samlp:Response/saml:Assertion', namespaces)

        evil = original.dup
        evil['ID'] = "_#{SecureRandom.uuid}"
        evil.at_xpath('./saml:Subject/saml:NameID', namespaces).content = 'attacker@evil.com'

        advice = Nokogiri::XML::Node.new('Advice', document)
        advice.namespace = original.namespace
        advice.add_child(original.dup)
        evil.at_xpath('./saml:Conditions', namespaces).add_next_sibling(advice)

        original.replace(evil)
        document.to_xml(save_with: as_xml)
      end

      it_behaves_like 'a rejected forgery'

      it 'reports the reference as unbound' do
        response.valid?
        expect(response.errors[:reference]).to be_present
      end
    end

    context 'when the original response is hidden in ds:Object' do
      let(:xml) do
        document = Nokogiri::XML(response_signed_xml)
        original = document.root
        hidden = original.dup

        evil = original.dup
        evil['ID'] = "_#{SecureRandom.uuid}"
        evil.at_xpath('.//saml:Assertion', namespaces)['ID'] = "_#{SecureRandom.uuid}"
        evil.at_xpath('.//saml:NameID', namespaces).content = 'attacker@evil.com'

        signature = evil.at_xpath('./ds:Signature', namespaces)
        object = Nokogiri::XML::Node.new('Object', document)
        object.namespace = signature.namespace
        object.add_child(hidden)
        signature.add_child(object)

        document.root = evil
        document.to_xml(save_with: as_xml)
      end

      it_behaves_like 'a rejected forgery'

      it 'reports the reference as unbound' do
        response.valid?
        expect(response.errors[:reference]).to be_present
      end
    end
  end
end
# rubocop:enable RSpec/DescribeClass
