RSpec.describe Saml::Kit::Builders::LogoutRequest do
  subject { described_class.new(user, configuration: configuration) }

  let(:user) { User.new(name_id: name_id) }
  let(:name_id) { SecureRandom.uuid }
  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.generate_key_pair_for(use: :signing)
    end
  end

  it 'produces the expected xml' do
    travel_to 1.second.from_now
    subject.id = Xml::Kit::Id.generate
    subject.destination = FFaker::Internet.http_url
    subject.issuer = FFaker::Internet.http_url
    subject.name_id_format = Saml::Kit::Namespaces::TRANSIENT

    result = subject.to_xml
    xml_hash = Hash.from_xml(result)

    expect(xml_hash['LogoutRequest']['ID']).to eql(subject.id)
    expect(xml_hash['LogoutRequest']['Version']).to eql('2.0')
    expect(xml_hash['LogoutRequest']['IssueInstant']).to eql(Time.now.utc.iso8601)
    expect(xml_hash['LogoutRequest']['Destination']).to eql(subject.destination)

    expect(xml_hash['LogoutRequest']['Issuer']).to eql(subject.issuer)
    expect(xml_hash['LogoutRequest']['NameID']).to eql(name_id)
    expect(result).to have_xpath("//samlp:LogoutRequest//saml:NameID[@Format=\"#{subject.name_id_format}\"]")
  end

  it 'includes a signature by default' do
    xml_hash = Hash.from_xml(subject.to_xml)
    expect(xml_hash['LogoutRequest']['Signature']).to be_present
  end

  it 'excludes a signature' do
    subject.embed_signature = false
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
