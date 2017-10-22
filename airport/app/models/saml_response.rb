class SamlResponse
  def initialize(xml)
    @xml = xml
    @hash = Hash.from_xml(xml)
  end

  def name_id
    @hash['Response']['Assertion']['Subject']['NameID']
  end

  def [](key)
    item = @hash['Response']['Assertion']['AttributeStatement']['Attribute'].find do |x|
      x['Name'] == key.to_s
    end
    item['AttributeValue']
  end

  def to_xml
    @xml
  end

  def self.parse(saml_response)
    new(Base64.decode64(saml_response))
  end
end
