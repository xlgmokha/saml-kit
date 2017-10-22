require 'spec_helper'

describe SamlRequest do
  describe ".build" do
    subject { described_class }

    it 'returns a compressed and base64 encoded document' do
      xml = "<xml></xml>"
      document = double(to_xml: xml)
      expect(subject.build(document)).to eql(Base64.encode64(xml))
    end
  end
end
