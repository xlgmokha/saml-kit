require 'spec_helper'

RSpec.describe Saml::Kit::Bindings do
  describe ".to_symbol" do
    subject { described_class }

    it { expect(subject.to_symbol(Saml::Kit::Bindings::HTTP_POST)).to eql(:http_post) }
    it { expect(subject.to_symbol(Saml::Kit::Bindings::HTTP_REDIRECT)).to eql(:http_redirect) }
    it { expect(subject.to_symbol('unknown')).to eql('unknown') }
  end

  describe ".create_for" do
    subject { described_class }
    let(:location) { FFaker::Internet.uri("https") }

    it 'returns an HTTP redirect binding' do
      expect(
        subject.create_for(Saml::Kit::Bindings::HTTP_REDIRECT, location)
      ).to be_instance_of(Saml::Kit::Bindings::HttpRedirect)
    end

    it 'returns an HTTP Post binding' do
      expect(
        subject.create_for(Saml::Kit::Bindings::HTTP_POST, location)
      ).to be_instance_of(Saml::Kit::Bindings::HttpPost)
    end

    it 'returns an unknown binding' do
      expect(
        subject.create_for(Saml::Kit::Bindings::HTTP_ARTIFACT, location)
      ).to be_instance_of(Saml::Kit::Bindings::Binding)
    end
  end
end
