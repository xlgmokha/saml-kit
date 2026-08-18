# frozen_string_literal: true

RSpec.describe Saml::Kit::XsdValidatable do
  let(:metadata_xml) do
    Saml::Kit::IdentityProviderMetadata.build do |x|
      x.entity_id = 'https://idp.example.com/metadata'
      x.add_single_sign_on_service(
        'https://idp.example.com/login', binding: :http_post
      )
    end.to_xml
  end

  let(:request_xml) do
    Saml::Kit::AuthenticationRequest.build do |x|
      x.issuer = 'https://sp.example.com/metadata'
    end.to_xml
  end

  describe 'concurrent validation' do
    # Compiling the schema inside Dir.chdir mutated process global state, and
    # ruby raises when one thread enters a chdir block while another is inside
    # one, so this raised "conflicting chdir during another chdir block".
    it 'does not raise when many threads validate at once' do
      threads = 8.times.map do
        Thread.new do
          20.times do
            Saml::Kit::IdentityProviderMetadata.new(metadata_xml).valid?
            Saml::Kit::AuthenticationRequest.new(request_xml).valid?
          end
        end
      end
      expect { threads.each(&:value) }.not_to raise_error
    end

    it 'reports the same result in every thread' do
      threads = 8.times.map do
        Thread.new { Saml::Kit::IdentityProviderMetadata.new(metadata_xml).valid? }
      end
      expect(threads.map(&:value).uniq).to eql([true])
    end
  end

  describe 'schema resolution' do
    # Our xsds import each other by relative filename, so this fails if they
    # ever resolve against the working directory instead of the xsd's own.
    it 'validates from an unrelated working directory' do
      Dir.chdir('/') do
        expect(Saml::Kit::IdentityProviderMetadata.new(metadata_xml)).to be_valid
      end
    end
  end

  describe 'schema compilation' do
    around do |example|
      cached = described_class.instance_variable_get(:@schemas)
      described_class.instance_variable_set(:@schemas, {})
      example.run
      described_class.instance_variable_set(:@schemas, cached)
    end

    it 'compiles a schema once however often it is validated' do
      allow(Nokogiri::XML::Schema).to receive(:from_document).and_call_original
      3.times { Saml::Kit::IdentityProviderMetadata.new(metadata_xml).valid? }
      expect(Nokogiri::XML::Schema).to have_received(:from_document).once
    end
  end
end
