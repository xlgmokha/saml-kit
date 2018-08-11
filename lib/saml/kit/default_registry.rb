# frozen_string_literal: true

module Saml
  module Kit
    # The default metadata registry is used to fetch the metadata associated
    # with an issuer or entity id.
    # The metadata associated with an issuer is used to verify trust for any
    # SAML documents that are received.
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
    # {include:file:spec/saml/kit/default_registry_spec.rb}
    class DefaultRegistry
      include Enumerable

      def initialize(items = {})
        @items = items
      end

      # Register a metadata document
      #
      # @param metadata [Saml::Kit::Metadata] the metadata to register.
      def register(metadata)
        ensure_valid_metadata(metadata)
        Saml::Kit.logger.debug(metadata.to_xml(pretty: true))
        @items[metadata.entity_id] = metadata
      end

      # Register metadata via a remote URL.
      # This will attempt to connect to the remove URL to download the
      # metadata and register it in the registry.
      #
      # @param url [String] the url to download the metadata from.
      # @param verify_ssl [Boolean] enable/disable SSL peer verification.
      def register_url(url, verify_ssl: true)
        headers = { 'User-Agent' => "saml/kit #{Saml::Kit::VERSION}" }
        verify_mode = verify_ssl ? nil : OpenSSL::SSL::VERIFY_NONE
        client = Net::Hippie::Client.new(headers: headers, verify_mode: verify_mode)
        register(Saml::Kit::Metadata.from(client.get(url).body))
      end

      # Returns the metadata document associated with an issuer or entityID.
      #
      # @param entity_id [String] unique entityID/Issuer associated with
      # metadata.
      def metadata_for(entity_id)
        @items[entity_id]
      end

      # Yields each registered [Saml::Kit::Metadata] to the block.
      def each
        @items.each_value do |value|
          yield value
        end
      end

      protected

      def ensure_valid_metadata(metadata)
        error = ArgumentError.new('Cannot register invalid metadata')
        raise error if
          metadata.nil? ||
          !metadata.respond_to?(:entity_id) ||
          metadata.invalid?
      end
    end
  end
end
