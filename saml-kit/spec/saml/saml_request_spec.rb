require 'spec_helper'

RSpec.describe Saml::Kit::SamlRequest do
  describe ".encode" do
    subject { described_class }

    it 'returns a compressed and base64 encoded document' do
      xml = "<xml></xml>"
      document = double(to_xml: xml)
      expect(subject.encode(document)).to eql(Base64.encode64(xml))
    end
  end
end
