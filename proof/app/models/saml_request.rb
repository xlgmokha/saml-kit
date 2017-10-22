class SamlRequest
  def self.decode(raw_request)
    new(Base64.decode64(raw_request))
  end
end
