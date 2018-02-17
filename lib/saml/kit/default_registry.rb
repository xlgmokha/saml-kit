module Saml
  module Kit
    # The default metadata registry is used to fetch the metadata associated with an issuer or entity id.
    # The metadata associated with an issuer is used to verify trust for any SAML documents that are received.
    #
    # You can replace the default registry with your own at startup.
    #
    # Example:
    #
    #   class OnDemandRegistry
    #    def initialize(original)
    #      @original = original
    #    end
    #
    #    def metadata_for(entity_id)
    #      found = @original.metadata_for(entity_id)
    #      return found if found
    #
    #      @original.register_url(entity_id, verify_ssl: Rails.env.production?)
    #      @original.metadata_for(entity_id)
    #    end
    #   end
    #
    #   Saml::Kit.configure do |configuration|
    #     configuration.entity_id = ENV['ENTITY_ID']
    #     configuration.registry = OnDemandRegistry.new(configuration.registry)
    #     configuration.logger = Rails.logger
    #   end
    #
    # {include:file:spec/saml/default_registry_spec.rb}
    class DefaultRegistry
      include Enumerable

      def initialize(items = {})
        @items = items
      end

      # Register a metadata document
      #
      # @param metadata [Saml::Kit::Metadata] the metadata to register.
      def register(metadata)
        Saml::Kit.logger.debug(metadata.to_xml(pretty: true))
        @items[metadata.entity_id] = metadata
      end

      # Register metadata via a remote URL.
      # This will attempt to connect to the remove URL to download the metadata and register it in the registry.
      #
      # @param url [String] the url to download the metadata from.
      # @param verify_ssl [Boolean] enable/disable SSL peer verification.
      def register_url(url, verify_ssl: true)
        content = HttpApi.new(url, verify_ssl: verify_ssl).get
        register(Saml::Kit::Metadata.from(content))
      end

      # Returns the metadata document associated with an issuer or entityID.
      #
      # @param entity_id [String] the unique entityID/Issuer associated with metadata.
      def metadata_for(entity_id)
        @items[entity_id]
      end

      # Yields each registered [Saml::Kit::Metadata] to the block.
      def each
        @items.each_value do |value|
          yield value
        end
      end

      class HttpApi # :nodoc:
        def initialize(url, verify_ssl: true)
          @uri = URI.parse(url)
          @verify_ssl = verify_ssl
        end

        def get
          execute(Net::HTTP::Get.new(uri.request_uri)).body
        end

        def execute(request)
          http.request(request)
        end

        private

        attr_reader :uri, :verify_ssl

        def http
          http = Net::HTTP.new(uri.host, uri.port)
          http.read_timeout = 30
          http.use_ssl = uri.is_a?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless verify_ssl
          http.set_debug_output(Saml::Kit.logger)
          http
        end
      end
    end
  end
end
