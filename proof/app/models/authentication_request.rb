class AuthenticationRequest
  def initialize(xml, registry = {})
    @xml = xml
    @registry = registry
    @hash = Hash.from_xml(@xml)
  end

  def issuer
    @hash['AuthnRequest']['Issuer']
  end

  def valid?
    @registry.registered?(issuer)
  end

  def to_xml
    @xml
  end
end
