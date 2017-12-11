require 'spec_helper'

RSpec.describe Saml::Kit::Certificate do
  subject { Saml::Kit.configuration.signing_certificate }

  describe "#fingerprint" do
    it 'returns a fingerprint' do
      expect(subject.fingerprint).to be_instance_of(Saml::Kit::Fingerprint)
    end
  end
end
