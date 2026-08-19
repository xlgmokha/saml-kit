# frozen_string_literal: true

RSpec.describe Saml::Kit::SubjectConfirmation do
  subject(:confirmation) { described_class.new(node) }

  let(:node) do
    Nokogiri::XML(xml).at_xpath(
      '//saml:SubjectConfirmation', 'saml' => Saml::Kit::Namespaces::ASSERTION
    )
  end

  let(:xml) do
    <<-XML.strip_heredoc
      <saml:Subject xmlns:saml="#{Saml::Kit::Namespaces::ASSERTION}">
        <saml:SubjectConfirmation Method="#{method}">
          <saml:SubjectConfirmationData #{attributes}/>
        </saml:SubjectConfirmation>
      </saml:Subject>
    XML
  end

  let(:method) { Saml::Kit::Namespaces::BEARER }
  let(:attributes) { '' }

  describe '#bearer?' do
    it 'is true for the bearer method' do
      expect(confirmation).to be_bearer
      expect(confirmation.confirmation_method).to eql(Saml::Kit::Namespaces::BEARER)
    end

    context 'when the method is holder of key' do
      let(:method) { "#{Saml::Kit::Namespaces::SAML_2_0}:cm:holder-of-key" }

      it 'is false' do
        expect(confirmation).not_to be_bearer
      end
    end
  end

  describe 'SubjectConfirmationData attributes' do
    let(:attributes) do
      'Recipient="https://sp.example.com/acs" ' \
        'InResponseTo="_abc" ' \
        'NotOnOrAfter="2026-08-17T12:05:00Z" ' \
        'NotBefore="2026-08-17T12:00:00Z"'
    end

    it 'reads each one' do
      expect(confirmation.recipient).to eql('https://sp.example.com/acs')
      expect(confirmation.in_response_to).to eql('_abc')
      expect(confirmation.expired_at).to eql(DateTime.parse('2026-08-17T12:05:00Z'))
      expect(confirmation.started_at).to eql(DateTime.parse('2026-08-17T12:00:00Z'))
    end

    it 'is expired at NotOnOrAfter, not after it' do
      expect(confirmation.expired?(DateTime.parse('2026-08-17T12:04:59Z'))).to be(false)
      expect(confirmation.expired?(DateTime.parse('2026-08-17T12:05:00Z'))).to be(true)
    end
  end

  describe 'absent attributes' do
    it 'returns nil rather than a default instant' do
      expect(confirmation.recipient).to be_nil
      expect(confirmation.in_response_to).to be_nil
      expect(confirmation.expired_at).to be_nil
      expect(confirmation.started_at).to be_nil
    end

    # Distinguishing absent from expired matters: a missing NotOnOrAfter is a
    # structural defect, which is a different error from a window that closed.
    it 'is not expired when NotOnOrAfter is absent' do
      expect(confirmation.expired?(Time.now.to_datetime)).to be(false)
    end
  end

  describe 'an unparseable timestamp' do
    let(:attributes) { 'NotOnOrAfter="not-a-date"' }

    # Fails closed: garbage reads as long past rather than as no limit.
    it 'reads as the epoch' do
      expect(confirmation.expired_at).to eql(Time.at(0).to_datetime)
      expect(confirmation.expired?(Time.now.to_datetime)).to be(true)
    end
  end
end
