require 'spec_helper'

RSpec.describe Saml::Kit::LogoutRequest do
  subject { builder.build }
  let(:builder) { described_class::Builder.new(user) }
  let(:user) { double(:user, name_id_for: name_id) }
  let(:name_id) { SecureRandom.uuid }

  it 'parses the issuer' do
    builder.issuer = FFaker::Internet.http_url
    expect(subject.issuer).to eql(builder.issuer)
  end

  it 'parses the issue instant' do
    travel_to 1.second.from_now
    expect(subject.issue_instant).to eql(Time.now.utc.iso8601)
  end

  it 'parses the version' do
    expect(subject.version).to eql("2.0")
  end

  it 'parses the destination' do
    builder.destination = FFaker::Internet.http_url
    expect(subject.destination).to eql(builder.destination)
  end

  it 'parses the name_id' do
    expect(subject.name_id).to eql(name_id)
  end

  describe described_class::Builder do
    subject { described_class.new(user) }
    let(:user) { double(:user, name_id_for: name_id) }
    let(:name_id) { SecureRandom.uuid }

    it 'produces the expected xml' do
      travel_to 1.second.from_now
      subject.id = SecureRandom.uuid
      subject.destination = FFaker::Internet.http_url
      subject.issuer = FFaker::Internet.http_url
      subject.name_id_format = Saml::Kit::Namespaces::TRANSIENT

      result = subject.to_xml
      xml_hash = Hash.from_xml(result)

      expect(xml_hash['LogoutRequest']['ID']).to eql("_#{subject.id}")
      expect(xml_hash['LogoutRequest']['Version']).to eql("2.0")
      expect(xml_hash['LogoutRequest']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(xml_hash['LogoutRequest']['Destination']).to eql(subject.destination)

      expect(xml_hash['LogoutRequest']['Issuer']).to eql(subject.issuer)
      expect(xml_hash['LogoutRequest']['NameID']).to eql(name_id)
      expect(result).to have_xpath("//LogoutRequest//NameID[@Format=\"#{subject.name_id_format}\"]")
    end

    it 'includes a signature by default' do
      xml_hash = Hash.from_xml(subject.to_xml)
      expect(xml_hash['LogoutRequest']['Signature']).to be_present
    end

    it 'excludes a signature' do
      subject.sign = false
      xml_hash = Hash.from_xml(subject.to_xml)
      expect(xml_hash['LogoutRequest']['Signature']).to be_nil
    end

    it 'builds a LogoutRequest' do
      travel_to 1.second.from_now
      result = subject.build
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
      expect(result.to_xml).to eql(subject.to_xml)
    end
  end
end
