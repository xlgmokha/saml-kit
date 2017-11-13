class DeferredRegistry
  attr_reader :urls

  def initialize(original, urls: [])
    @urls = urls
    @original = original
  end

  def metadata_for(entity_id)
    if @bootstrapped.nil?
      @urls.each do |url|
        @original.register_url(url, verify_ssl: Rails.env.production?)
      end
      @bootstrapped = true
    end

    @original.metadata_for(entity_id)
  end
end

Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  configuration.registry = DeferredRegistry.new(configuration.registry, urls: ["http://localhost:3000/metadata"])
  configuration.logger = Rails.logger
end
