require "spec_helper"

RSpec.describe Saml::Kit do
  it "has a version number" do
    expect(Saml::Kit::VERSION).not_to be nil
  end
end