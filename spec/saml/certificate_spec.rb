require 'spec_helper'

RSpec.describe Saml::Kit::Certificate do
  subject { described_class.new(Saml::Kit.configuration.stripped_signing_certificate, use: :signing) }

  describe "#fingerprint" do
    it 'returns a fingerprint' do
      expect(subject.fingerprint).to be_instance_of(Saml::Kit::Fingerprint)
    end
  end
end
