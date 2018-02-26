RSpec.describe Saml::Kit::Document do
  subject do
    Saml::Kit::AuthenticationRequest.build do |x|
      x.id = id
      x.issuer = issuer
    end
  end

  let(:id) { Xml::Kit::Id.generate }
  let(:issuer) { FFaker::Internet.uri('https') }

  specify { expect(subject.id).to eql(id) }
  specify { expect(subject.issuer).to eql(issuer) }

  describe '.to_saml_document' do
    subject { described_class }

    let(:user) { User.new(attributes: { id: SecureRandom.uuid }) }
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: Xml::Kit::Id.generate, issuer: FFaker::Internet.http_url, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, provider: nil, signed?: true, trusted?: true) }

    it 'returns a Response' do
      xml = Saml::Kit::Response.build_xml(user, request)
      result = subject.to_saml_document(xml)
      expect(result).to be_instance_of(Saml::Kit::Response)
    end

    it 'returns a LogoutResponse' do
      xml = Saml::Kit::LogoutResponse.build_xml(request)
      result = subject.to_saml_document(xml)
      expect(result).to be_instance_of(Saml::Kit::LogoutResponse)
    end

    it 'returns an AuthenticationRequest' do
      xml = Saml::Kit::AuthenticationRequest.build_xml
      result = subject.to_saml_document(xml)
      expect(result).to be_instance_of(Saml::Kit::AuthenticationRequest)
    end

    it 'returns a LogoutRequest' do
      xml = Saml::Kit::LogoutRequest.build_xml(user)
      result = subject.to_saml_document(xml)
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
    end

    it 'returns an invalid document' do
      xml = <<-XML
      <html>
        <head></head>
        <body></body>
      </html>
      XML
      result = subject.to_saml_document(xml)
      expect(result).to be_instance_of(Saml::Kit::InvalidDocument)
    end

    it 'returns an invalid document when the xml is not XML' do
      result = subject.to_saml_document('NOT XML')
      expect(result).to be_instance_of(Saml::Kit::InvalidDocument)
    end

    it 'returns an invalid document when given nil' do
      result = subject.to_saml_document(nil)
      expect(result).to be_instance_of(Saml::Kit::InvalidDocument)
    end
  end
end
