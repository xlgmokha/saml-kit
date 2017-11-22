require 'spec_helper'

RSpec.describe Saml::Kit::Xml do
  describe "#valid_signature?" do
    let(:login_url) { "https://#{FFaker::Internet.domain_name}/login" }
    let(:logout_url) { "https://#{FFaker::Internet.domain_name}/logout" }

    let(:signed_xml) do
      builder = Saml::Kit::ServiceProviderMetadata::Builder.new
      builder.entity_id = FFaker::Movie.title
      builder.add_assertion_consumer_service(login_url, binding: :http_post)
      builder.add_assertion_consumer_service(login_url, binding: :http_redirect)
      builder.add_single_logout_service(logout_url, binding: :http_post)
      builder.add_single_logout_service(logout_url, binding: :http_redirect)
      builder.to_xml
    end

    it 'returns true, when the digest and signature is valid' do
      subject = described_class.new(signed_xml)
      expect(subject).to be_valid
    end

    it 'returns false, when the SHA1 digest is not valid' do
      subject = described_class.new(signed_xml.gsub("EntityDescriptor", "uhoh"))
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'it is invalid when digest is incorrect' do
      old_digest = Hash.from_xml(signed_xml)['EntityDescriptor']['Signature']['SignedInfo']['Reference']['DigestValue']
      subject = described_class.new(signed_xml.gsub(old_digest, 'sabotage'))
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'returns false, when the signature is invalid' do
      old_signature = Hash.from_xml(signed_xml)['EntityDescriptor']['Signature']['SignatureValue']
      signed_xml.gsub!(old_signature, 'sabotage')
      subject = described_class.new(signed_xml)
      expect(subject).to_not be_valid
      expect(subject.errors[:signature]).to be_present
    end
  end
end
