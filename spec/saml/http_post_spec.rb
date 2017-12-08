require 'spec_helper'

RSpec.describe Saml::Kit::Bindings::HttpPost do
  describe "equality" do
    let(:location) { FFaker::Internet.uri("https") }
    subject { Saml::Kit::Bindings::HttpPost.new(location: location) }

    it 'is referentially equal' do
      expect(subject).to eql(subject)
    end

    it 'is equal by value' do
      expect(subject).to eql(
        Saml::Kit::Bindings::HttpPost.new(location: location)
      )
    end

    it 'is not equal' do
      expect(subject).to_not eql(
        Saml::Kit::Bindings::HttpPost.new(
          location: FFaker::Internet.uri("https")
        )
      )
    end
  end
end
