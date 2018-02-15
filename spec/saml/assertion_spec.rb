RSpec.describe Saml::Kit::Assertion do
  describe "#active?" do
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.session_timeout = 30.minutes
        config.clock_drift = 30.seconds
      end
    end

    it 'is valid after a valid session window + drift' do
      now = Time.current
      travel_to now
      not_on_or_after = configuration.session_timeout.since(now).iso8601
      xml = <<-XML
<Response>
<Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{Xml::Kit::Id.generate}" IssueInstant="#{now.iso8601}" Version="2.0">
 <Issuer>#{FFaker::Internet.uri("https")}</Issuer>
 <Subject>
   <NameID Format="#{Saml::Kit::Namespaces::PERSISTENT}">#{SecureRandom.uuid}</NameID>
   <SubjectConfirmation Method="#{Saml::Kit::Namespaces::BEARER}">
     <SubjectConfirmationData InResponseTo="#{SecureRandom.uuid}" NotOnOrAfter="#{not_on_or_after}" Recipient="#{FFaker::Internet.uri("https")}"/>
   </SubjectConfirmation>
 </Subject>
 <Conditions NotBefore="#{now.utc.iso8601}" NotOnOrAfter="#{not_on_or_after}">
   <AudienceRestriction>
     <Audience>#{FFaker::Internet.uri("https")}</Audience>
   </AudienceRestriction>
 </Conditions>
 <AuthnStatement AuthnInstant="#{now.utc.iso8601}" SessionIndex="#{Xml::Kit::Id.generate}" SessionNotOnOrAfter="#{not_on_or_after}">
   <AuthnContext>
     <AuthnContextClassRef>#{Saml::Kit::Namespaces::PASSWORD}</AuthnContextClassRef>
   </AuthnContext>
 </AuthnStatement>
</Assertion>
</Response>
XML
      subject = described_class.new(Nokogiri::XML(xml), configuration: configuration)
      travel_to (configuration.clock_drift - 1.second).before(now)
      expect(subject).to be_active
      expect(subject).to_not be_expired
    end

    it 'interprets integers correctly' do
      configuration.clock_drift = 30
      now = Time.current
      travel_to now
      not_before = now.utc.iso8601
      not_after = configuration.session_timeout.since(now).iso8601
      xml = <<-XML
<Response>
<Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{Xml::Kit::Id.generate}" IssueInstant="#{now.iso8601}" Version="2.0">
 <Issuer>#{FFaker::Internet.uri("https")}</Issuer>
 <Subject>
   <NameID Format="#{Saml::Kit::Namespaces::PERSISTENT}">#{SecureRandom.uuid}</NameID>
   <SubjectConfirmation Method="#{Saml::Kit::Namespaces::BEARER}">
     <SubjectConfirmationData InResponseTo="#{SecureRandom.uuid}" NotOnOrAfter="#{not_after}" Recipient="#{FFaker::Internet.uri("https")}"/>
   </SubjectConfirmation>
 </Subject>
 <Conditions NotBefore="#{not_before}" NotOnOrAfter="#{not_after}">
   <AudienceRestriction>
     <Audience>#{FFaker::Internet.uri("https")}</Audience>
   </AudienceRestriction>
 </Conditions>
 <AuthnStatement AuthnInstant="#{now.utc.iso8601}" SessionIndex="#{Xml::Kit::Id.generate}" SessionNotOnOrAfter="#{not_after}">
   <AuthnContext>
     <AuthnContextClassRef>#{Saml::Kit::Namespaces::PASSWORD}</AuthnContextClassRef>
   </AuthnContext>
 </AuthnStatement>
</Assertion>
</Response>
XML
      subject = described_class.new(Nokogiri::XML(xml), configuration: configuration)
      expect(subject).to be_active
      expect(subject).to_not be_expired
    end
  end

  describe "#present?" do
    it 'returns false when the assertion is empty' do
      subject = described_class.new(nil)
      expect(subject).to_not be_present
    end

    it 'returns true when the assertion is present' do
      not_before = Time.now.utc.iso8601
      not_after = 10.minutes.from_now.iso8601
      xml = <<-XML
<Response>
<Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="#{Xml::Kit::Id.generate}" IssueInstant="#{Time.now.iso8601}" Version="2.0">
 <Issuer>#{FFaker::Internet.uri("https")}</Issuer>
 <Subject>
   <NameID Format="#{Saml::Kit::Namespaces::PERSISTENT}">#{SecureRandom.uuid}</NameID>
   <SubjectConfirmation Method="#{Saml::Kit::Namespaces::BEARER}">
     <SubjectConfirmationData InResponseTo="#{SecureRandom.uuid}" NotOnOrAfter="#{not_after}" Recipient="#{FFaker::Internet.uri("https")}"/>
   </SubjectConfirmation>
 </Subject>
 <Conditions NotBefore="#{not_before}" NotOnOrAfter="#{not_after}">
   <AudienceRestriction>
     <Audience>#{FFaker::Internet.uri("https")}</Audience>
   </AudienceRestriction>
 </Conditions>
 <AuthnStatement AuthnInstant="#{Time.now.utc.iso8601}" SessionIndex="#{Xml::Kit::Id.generate}" SessionNotOnOrAfter="#{not_after}">
   <AuthnContext>
     <AuthnContextClassRef>#{Saml::Kit::Namespaces::PASSWORD}</AuthnContextClassRef>
   </AuthnContext>
 </AuthnStatement>
</Assertion>
</Response>
XML
      subject = described_class.new(Nokogiri::XML(xml))
      expect(subject).to be_present
    end
  end
end
