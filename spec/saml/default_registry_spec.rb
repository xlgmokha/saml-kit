require 'spec_helper'

RSpec.describe Saml::Kit::DefaultRegistry do
  subject { described_class.new }

  describe "#service_provider_metadata_for" do
    let(:entity_id) { FFaker::Internet.http_url }
    let(:service_provider_metadata) do
      builder = Saml::Kit::ServiceProviderMetadata::Builder.new
      builder.entity_id = entity_id
      builder.build
    end

    it 'returns the metadata for the entity_id' do
      subject.register(service_provider_metadata)
      expect(subject.service_provider_metadata_for(entity_id)).to eql(service_provider_metadata)
    end
  end
end
