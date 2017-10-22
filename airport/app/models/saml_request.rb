class SamlRequest
  def self.build(document)
    new(document.to_xml).to_s
  end

  def initialize(raw_xml)
    @xml = encode(compress(raw_xml))
  end

  def to_s
    @xml
  end

  private

  def encode(xml)
    Base64.encode64(xml)
  end

  def compress(xml)
    xml
    #Zlib::Deflate.deflate(xml, 9)[2..-5]
  end
end
