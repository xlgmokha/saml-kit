# frozen_string_literal: true

RSpec.describe Saml::Kit::Response do
  subject { described_class.build(user, request) }

  let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: ::Xml::Kit::Id.generate, issuer: FFaker::Internet.uri('https'), assertion_consumer_service_url: FFaker::Internet.uri('https'), name_id_format: Saml::Kit::Namespaces::PERSISTENT, provider: nil, signed?: true, trusted?: true) }
  let(:user) { User.new(attributes: { id: SecureRandom.uuid }) }

  specify { expect(subject.status_code).to eql(Saml::Kit::Namespaces::SUCCESS) }
  specify { expect(subject.in_response_to).to eql(request.id) }

  describe '#valid?' do
    subject { described_class.build(user, request, configuration: configuration) }

    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::IdentityProviderMetadata) }

    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.entity_id = request.issuer
        config.registry = registry
        config.generate_key_pair_for(use: :signing)
      end
    end

    it 'is valid' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      expect(subject).to be_valid
    end

    it 'is invalid when blank' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = described_class.new('')
      expect(subject).to be_invalid
      expect(subject.errors[:content]).to be_present
      expect(subject.errors[:assertion]).to match_array(['is missing.'])
    end

    it 'is invalid if the document has been tampered with' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      status_code = FFaker::Movie.title
      xml = described_class.build(user, request) do |builder|
        builder.status_code = status_code
      end.to_xml.gsub(status_code, 'TAMPERED')
      subject = described_class.new(xml)
      expect(subject).to be_invalid
    end

    it 'is invalid when not a Response' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = described_class.new(Saml::Kit::IdentityProviderMetadata.build.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(false)
      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'validates the schema of the response' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      id = Xml::Kit::Id.generate
      key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
      signed_xml = ::Xml::Kit::Signatures.sign(key_pair: key_pair) do |xml, signature|
        xml.tag! 'samlp:Response', 'xmlns:samlp' => Saml::Kit::Namespaces::PROTOCOL, ID: id do
          signature.template(id)
          xml.Fake do
            xml.NotAllowed 'Huh?'
          end
        end
      end
      subject = described_class.new(signed_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to be_present
    end

    it 'validates the version' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.build(user, request) do |builder|
        builder.version = '1.1'
      end
      expect(subject).to be_invalid
      expect(subject.errors[:version]).to be_present
    end

    it 'validates the id' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.build(user, request) do |builder|
        builder.id = nil
      end
      expect(subject).to be_invalid
      expect(subject.errors[:id]).to be_present
    end

    it 'validates the status code' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.build(user, request) do |builder|
        builder.status_code = Saml::Kit::Namespaces::REQUESTER_ERROR
      end
      expect(subject).to be_invalid
      expect(subject.errors[:status_code]).to be_present
    end

    it 'validates the InResponseTo' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      xml = described_class.build(user, request).to_xml
      subject = described_class.new(xml, request_id: SecureRandom.uuid)

      expect(subject).to be_invalid
      expect(subject.errors[:in_response_to]).to be_present
    end

    it 'is invalid after a valid session window' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      subject = described_class.build(user, request)
      travel_to Saml::Kit.configuration.session_timeout.from_now + 5.seconds
      expect(subject).not_to be_valid
      expect(subject.errors[:assertion]).to match_array(['must not be expired.'])
    end

    it 'is invalid before the valid session window' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      subject = described_class.build(user, request)
      travel_to((Saml::Kit.configuration.clock_drift + 1.second).before(Time.now))
      expect(subject).to be_invalid
      expect(subject.errors[:assertion]).to match_array(['must not be expired.'])
    end

    it 'is invalid when the audience does not match the expected issuer' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      allow(configuration).to receive(:issuer).and_return(FFaker::Internet.uri('https'))
      allow(request).to receive(:issuer).and_return(FFaker::Internet.uri('https'))

      expect(subject).to be_invalid
      expect(subject.errors[:audience]).to be_present
    end

    it 'is invalid' do
      now = Time.now.utc
      destination = FFaker::Internet.uri('https')
      raw_xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{Xml::Kit::Id.generate}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{destination}" Consent="#{Saml::Kit::Namespaces::UNSPECIFIED}" InResponseTo="#{request.id}">
          <Issuer xmlns="#{Saml::Kit::Namespaces::ASSERTION}">#{request.issuer}</Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="#{Saml::Kit::Namespaces::RESPONDER_ERROR}"/>
          </samlp:Status>
        </samlp:Response>
      XML

      allow(registry).to receive(:metadata_for).with(request.issuer).and_return(metadata)
      subject = described_class.new(raw_xml)
      expect(subject).to be_invalid
    end

    it 'is invalid when there are 2 assertions' do
      id = Xml::Kit::Id.generate
      issuer = FFaker::Internet.uri('https')
      key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
      response_options = {
        ID: id,
        Version: '2.0',
        IssueInstant: Time.now.iso8601,
        Consent: Saml::Kit::Namespaces::UNSPECIFIED,
        InResponseTo: request.id,
        xmlns: Saml::Kit::Namespaces::PROTOCOL,
      }
      assertion_options = {
        ID: Xml::Kit::Id.generate,
        IssueInstant: Time.now.iso8601,
        Version: '2.0',
        xmlns: Saml::Kit::Namespaces::ASSERTION,
      }
      raw_xml = ::Xml::Kit::Signatures.sign(key_pair: key_pair) do |xml, signature|
        xml.instruct!
        xml.Response response_options do
          xml.Issuer(issuer, xmlns: Saml::Kit::Namespaces::ASSERTION)
          xml.Status do
            xml.StatusCode Value: Saml::Kit::Namespaces::SUCCESS
          end
          xml.Assertion(assertion_options) do
            xml.Issuer issuer
            signature.template(assertion_options[:ID])
            xml.Subject do
              xml.NameID FFaker::Internet.email, Format: Saml::Kit::Namespaces::EMAIL_ADDRESS
              xml.SubjectConfirmation Method: Saml::Kit::Namespaces::BEARER do
                xml.SubjectConfirmationData '', InResponseTo: request.id, NotOnOrAfter: 3.hours.from_now.utc.iso8601, Recipient: FFaker::Internet.uri('https')
              end
            end
            xml.Conditions NotBefore: Time.now.utc.iso8601, NotOnOrAfter: 3.hours.from_now.utc.iso8601 do
              xml.AudienceRestriction do
                xml.Audience request.issuer
              end
            end
            xml.AuthnStatement AuthnInstant: Time.now.iso8601, SessionIndex: assertion_options[:ID], SessionNotOnOrAfter: 3.hours.from_now.utc.iso8601 do
              xml.AuthnContext do
                xml.AuthnContextClassRef Saml::Kit::Namespaces::PASSWORD
              end
            end
          end
          new_options = assertion_options.merge(ID: Xml::Kit::Id.generate)
          xml.Assertion(new_options) do
            xml.Issuer issuer
            xml.Subject do
              xml.NameID FFaker::Internet.email, Format: Saml::Kit::Namespaces::EMAIL_ADDRESS
              xml.SubjectConfirmation Method: Saml::Kit::Namespaces::BEARER do
                xml.SubjectConfirmationData '', InResponseTo: request.id, NotOnOrAfter: 3.hours.from_now.utc.iso8601, Recipient: FFaker::Internet.uri('https')
              end
            end
            xml.Conditions NotBefore: Time.now.utc.iso8601, NotOnOrAfter: 3.hours.from_now.utc.iso8601 do
              xml.AudienceRestriction do
                xml.Audience request.issuer
              end
            end
            xml.AuthnStatement AuthnInstant: Time.now.iso8601, SessionIndex: new_options[:ID], SessionNotOnOrAfter: 3.hours.from_now.utc.iso8601 do
              xml.AuthnContext do
                xml.AuthnContextClassRef Saml::Kit::Namespaces::PASSWORD
              end
            end
          end
        end
      end
      subject = described_class.new(raw_xml)
      expect(subject).not_to be_valid
      expect(subject.errors.full_messages).to include('must contain a single Assertion.')
    end

    it 'is invalid if there are two assertions (one signed and the other unsigned)' do
      raw_xml = IO.read('spec/fixtures/unsigned_response_two_assertions.xml')
      subject = described_class.new(raw_xml)
      expect(subject).not_to be_valid
      expect(subject.errors.full_messages).to include('must contain a single Assertion.')
    end

    it 'is invalid when the assertion has a signature and has been tampered with' do
      user = User.new(attributes: { token: SecureRandom.uuid })
      request = Saml::Kit::AuthenticationRequest.build
      document = described_class.build(user, request, configuration: configuration) do |x|
        x.embed_signature = false
        x.assertion.embed_signature = true
      end

      altered_xml = document.to_xml.gsub(/token/, 'heck')
      subject = described_class.new(altered_xml)
      expect(subject).not_to be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'is invalid when we do not have a private key to decrypt the assertion' do
      xml = described_class.build_xml(user, request) do |x|
        x.encrypt_with(::Xml::Kit::KeyPair.generate(use: :encryption))
      end

      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:assertion]).to match_array(['cannot be decrypted.'])
    end
  end

  describe '#signed?' do
    let(:now) { Time.now.utc }
    let(:id) { Xml::Kit::Id.generate }
    let(:url) { FFaker::Internet.uri('https') }

    it 'returns true when the Assertion is signed' do
      xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
          <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0">
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="##{id}">
                  <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  </ds:Transforms>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue></ds:SignatureValue>
              <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                  <ds:X509Certificate></ds:X509Certificate>
                </ds:X509Data>
              </KeyInfo>
            </ds:Signature>
          </Assertion>
        </samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject).not_to be_signed
      expect(subject.assertion).to be_signed
    end

    it 'returns true when the Response is signed' do
      xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference URI="##{id}">
                <ds:Transforms>
                  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                  <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue></ds:DigestValue>
              </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
              <ds:X509Data>
                <ds:X509Certificate></ds:X509Certificate>
              </ds:X509Data>
            </KeyInfo>
          </ds:Signature>
          <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
        </samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject).to be_signed
    end

    it 'returns false when there is no signature' do
      xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
          <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
        </samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject).not_to be_signed
    end
  end

  describe '#certificate' do
    let(:now) { Time.now.utc }
    let(:id) { Xml::Kit::Id.generate }
    let(:url) { FFaker::Internet.uri('https') }
    let(:certificate) do
      ::Xml::Kit::Certificate.new(
        ::Xml::Kit::SelfSignedCertificate.new.create(passphrase: 'password')[0],
        use: :signing
      )
    end

    it 'returns the certificate when the Assertion is signed' do
      xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
          <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0">
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="##{id}">
                  <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  </ds:Transforms>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue></ds:SignatureValue>
              <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                  <ds:X509Certificate>#{certificate.stripped}</ds:X509Certificate>
                </ds:X509Data>
              </KeyInfo>
            </ds:Signature>
          </Assertion>
        </samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject.signature).not_to be_present
      expect(subject.assertion.signature).to be_present
      expect(subject.assertion.signature.certificate.stripped).to eql(certificate.stripped)
    end

    it 'returns the certificate when the Response is signed' do
      xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference URI="##{id}">
                <ds:Transforms>
                  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                  <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue></ds:DigestValue>
              </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
              <ds:X509Data>
                <ds:X509Certificate>#{certificate}</ds:X509Certificate>
              </ds:X509Data>
            </KeyInfo>
          </ds:Signature>
          <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
        </samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject.signature.certificate).to eql(certificate)
    end

    it 'returns nil when there is no signature' do
      xml = <<-XML.strip_heredoc
        <?xml version="1.0"?>
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
          <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
        </samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject.signature).not_to be_present
    end
  end

  describe 'encrypted assertion' do
    let(:id) { Xml::Kit::Id.generate }
    let(:now) { Time.now.utc }
    let(:assertion_consumer_service_url) { FFaker::Internet.uri('https') }
    let(:password) { FFaker::Movie.title }
    let(:email) { FFaker::Internet.email }
    let(:created_at) { Time.now }
    let(:assertion) do
      <<-XML.strip_heredoc
        <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" IssueInstant="2017-11-23T04:33:58Z" Version="2.0">
         <Issuer>#{FFaker::Internet.uri('https')}</Issuer>
         <Subject>
           <NameID Format="#{Saml::Kit::Namespaces::PERSISTENT}">#{SecureRandom.uuid}</NameID>
           <SubjectConfirmation Method="#{Saml::Kit::Namespaces::BEARER}">
             <SubjectConfirmationData InResponseTo="#{SecureRandom.uuid}" NotOnOrAfter="2017-11-23T07:33:58Z" Recipient="https://westyundt.ca/acs"/>
           </SubjectConfirmation>
         </Subject>
         <Conditions NotBefore="2017-11-23T04:33:58Z" NotOnOrAfter="2017-11-23T07:33:58Z">
           <AudienceRestriction>
             <Audience>American Wolves</Audience>
           </AudienceRestriction>
         </Conditions>
         <AuthnStatement AuthnInstant="2017-11-23T04:33:58Z" SessionIndex="_11d39a7f-1b86-43ed-90d7-68090a857ca8" SessionNotOnOrAfter="2017-11-23T07:33:58Z">
           <AuthnContext>
             <AuthnContextClassRef>#{Saml::Kit::Namespaces::PASSWORD}</AuthnContextClassRef>
           </AuthnContext>
         </AuthnStatement>
         <AttributeStatement>
           <Attribute Name="email" NameFormat="#{Saml::Kit::Namespaces::URI}">
             <AttributeValue>#{email}</AttributeValue>
           </Attribute>
           <Attribute Name="created_at" NameFormat="#{Saml::Kit::Namespaces::URI}">
             <AttributeValue>#{created_at.iso8601}</AttributeValue>
           </Attribute>
         </AttributeStatement>
        </Assertion>
      XML
    end

    it 'parses the encrypted assertion' do
      certificate_pem, private_key_pem = ::Xml::Kit::SelfSignedCertificate.new.create(passphrase: password)
      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
      private_key = OpenSSL::PKey::RSA.new(private_key_pem, password)

      allow(Saml::Kit.configuration).to receive(:private_keys).with(use: :encryption).and_return([private_key])

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      encrypted = cipher.update(assertion) + cipher.final

      xml = <<-XML.strip_heredoc
        <samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" xmlns:saml="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{assertion_consumer_service_url}" InResponseTo="#{Xml::Kit::Id.generate}">
          <saml:Issuer>#{FFaker::Internet.uri('https')}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="#{Saml::Kit::Namespaces::SUCCESS}"/>
          </samlp:Status>
          <saml:EncryptedAssertion>
            <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
            <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
            <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
              <xenc:EncryptedKey>
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
                <xenc:CipherData>
                  <xenc:CipherValue>#{Base64.encode64(public_key.public_encrypt(key))}</xenc:CipherValue>
                </xenc:CipherData>
              </xenc:EncryptedKey>
            </dsig:KeyInfo>
            <xenc:CipherData>
              <xenc:CipherValue>#{Base64.encode64(iv + encrypted)}</xenc:CipherValue>
            </xenc:CipherData>
            </xenc:EncryptedData>
          </saml:EncryptedAssertion>
        </samlp:Response>
      XML

      subject = described_class.new(xml)
      expect(subject.attributes).to match_array([
        ['created_at', created_at.iso8601],
        ['email', email]
      ])
    end
  end

  describe 'parsing' do
    let(:user) { User.new(attributes: attributes) }
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: Xml::Kit::Id.generate, signed?: true, trusted?: true, provider: nil, assertion_consumer_service_url: FFaker::Internet.uri('https'), name_id_format: '', issuer: FFaker::Internet.uri('https')) }
    let(:attributes) { { name: 'mo' } }

    it 'returns the name id' do
      subject = described_class.build(user, request)
      expect(subject.name_id).to eql(user.name_id)
    end

    it 'excludes comments from the name id' do
      user.name_id = 'shiro@voltron.com<!-- CVE-2017-11428 -->.evil.com'
      subject = described_class.build(user, request)
      expect(subject.name_id).to eql('shiro@voltron.com<!-- CVE-2017-11428 -->.evil.com')
      expect(subject.name_id).not_to eql('shiro@voltron.com')
    end

    it 'parses the name id safely (CVE-2017-11428)' do
      raw = IO.read('spec/fixtures/response_node_text_attack.xml.base64')
      subject = Saml::Kit::Bindings::HttpPost.new(location: '').deserialize({ 'SAMLResponse' => raw })
      expect(subject.name_id).to eql('support@onelogin.com')
      expect(subject.attributes[:surname]).to eql('smith')
    end

    it 'returns the single attributes' do
      subject = described_class.build(user, request)
      expect(subject.attributes).to eql('name' => 'mo')
    end

    it 'returns the multiple attributes' do
      attributes[:age] = 33
      subject = described_class.build(user, request)
      expect(subject.attributes).to eql('name' => 'mo', 'age' => '33')
    end

    it 'can parse an assertion without a name id' do
      xml = expand_template('no_nameid.saml_response', issue_instant: Time.now)
      subject = described_class.new(xml)
      expect(subject.name_id).to be_nil
    end

    it 'parses a response with a status code of Requester' do
      message = FFaker::Lorem.sentence
      subject = described_class.new(expand_template('requester_error.saml_response', status_message: message))
      expect(subject.status_code).to eql(Saml::Kit::Namespaces::REQUESTER_ERROR)
      expect(subject.status_message).to eql(message)
    end

    it 'parses an array of attributes' do
      attributes[:roles] = %i[admin user]
      subject = described_class.build(user, request)
      expect(subject.attributes[:roles]).to match_array(%w[admin user])
    end
  end

  describe '#build' do
    it 'can build a response without a request' do
      configuration = Saml::Kit::Configuration.new do |config|
        config.entity_id = FFaker::Internet.uri('https')
      end
      sp = Saml::Kit::Metadata.build(&:build_service_provider)
      allow(configuration.registry).to receive(:metadata_for).with(configuration.entity_id).and_return(sp)
      result = described_class.build(user, configuration: configuration)
      expect(result).to be_instance_of(described_class)
      expect(result).to be_valid
    end

    it 'can build a response without the need for the user to provide attributes' do
      configuration = Saml::Kit::Configuration.new do |config|
        config.entity_id = FFaker::Internet.uri('https')
      end
      sp = Saml::Kit::Metadata.build(&:build_service_provider)
      allow(configuration.registry).to receive(:metadata_for).with(configuration.entity_id).and_return(sp)
      user = UserWithoutAttributes.new

      result = described_class.build(user, configuration: configuration)
      expect(result).to be_instance_of(described_class)
      expect(result).to be_valid
      expect(result.attributes).to be_empty
    end
  end

  describe '.new' do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::IdentityProviderMetadata) }
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.entity_id = request.issuer
        config.registry = registry
        config.generate_key_pair_for(use: :signing)
      end
    end

    it 'parses a raw response' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      saml = described_class.build(user, request, configuration: configuration)
      expect(described_class.new(saml.to_xml, configuration: configuration)).to be_valid
    end
  end
end
