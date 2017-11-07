class BearerToken
  def initialize(private_key = Saml::Kit.configuration.signing_private_key)
    @private_key = private_key
    @public_key = private_key.public_key
  end

  def encode(payload)
    JWT.encode(timestamps.merge(payload), private_key, 'RS256')
  end

  def decode(token)
    JWT.decode(token, public_key, true, { algorithm: 'RS256' })[0].with_indifferent_access
  rescue
    {}
  end

  private

  attr_reader :private_key, :public_key

  def timestamps
    { exp: expiration.to_i, iat: issued_at.to_i }
  end

  def issued_at
    Time.current
  end

  def expiration
    1.hour.from_now
  end
end
