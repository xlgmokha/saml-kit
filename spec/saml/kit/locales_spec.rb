# frozen_string_literal: true

# Translatable#error_message scopes by the document's name, with no shared
# scope and no fallback, and it calls I18n.translate without raise: true. A
# missing key therefore renders the literal string "Translation missing: ..."
# rather than raising, and a spec asserting only that an error is present will
# not notice.
#
# LogoutRequest and LogoutResponse were missing invalid, invalid_version and
# unsigned before 1.6.0 for exactly that reason -- an assertion comparing
# `errors[:base]` against `error_message(:invalid)` passed because both sides
# produced the same broken string.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Error message translations' do
  # Every key reachable through a validation that Document or one of its
  # concerns defines, so every document name needs all of them.
  shared_keys = %i[
    invalid invalid_destination invalid_fingerprint invalid_version
    unregistered unsigned
  ]
  document_names = %w[Assertion AuthnRequest LogoutRequest LogoutResponse Response]

  def bare_document(name, configuration)
    xml = <<-XML.strip_heredoc
      <samlp:#{name} xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}"
                     xmlns:saml="#{Saml::Kit::Namespaces::ASSERTION}"
                     ID="#{::Xml::Kit::Id.generate}"
                     Version="2.0"
                     IssueInstant="#{Time.now.utc.iso8601}">
        <saml:Issuer>https://unregistered.example.com/metadata</saml:Issuer>
      </samlp:#{name}>
    XML
    Saml::Kit::Document.to_saml_document(xml, configuration: configuration)
  end

  document_names.each do |name|
    it "defines every shared error key for #{name}" do
      missing = shared_keys.reject do |key|
        I18n.exists?("saml/kit.errors.#{name}.#{key}")
      end
      expect(missing).to be_empty
    end
  end

  it 'renders a real message for every error on a rejected document' do
    configuration = Saml::Kit::Configuration.new do |config|
      config.entity_id = 'https://sp.example.com/metadata'
      config.logout_signature_required = true
    end

    messages = %w[Response LogoutRequest LogoutResponse AuthnRequest].flat_map do |name|
      document = bare_document(name, configuration)
      document.valid?
      document.errors.to_hash.values.flatten
    end

    expect(messages).to be_present
    expect(messages.grep(/Translation missing/)).to be_empty
  end
end
# rubocop:enable RSpec/DescribeClass
