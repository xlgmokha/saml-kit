class Configuration
  def issuer
    configuration.issuer
  end

  def acs_url
    configuration.acs_url
  end

  private

  def configuration
    Rails.configuration.x
  end
end
