require 'spec_helper'

RSpec.describe Saml::Kit::Certificate do
  #subject { Saml::Kit.configuration.certificates(use: :signing).last }
  subject { described_class.new(certificate, use: :signing) }
  let(:certificate) do
    cert, _ = Saml::Kit::SelfSignedCertificate.new('password').create
    cert
  end

  describe "#fingerprint" do
    it 'returns a fingerprint' do
      expect(subject.fingerprint).to be_instance_of(Saml::Kit::Fingerprint)
    end
  end
end
