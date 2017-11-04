module Saml
  module Kit
    class DefaultRegistry
      def initialize(items = {})
        @items = items
      end

      def register(metadata)
        @items[metadata.entity_id] = metadata
      end

      def service_provider_metadata_for(entity_id)
        @items[entity_id]
      end
    end
  end
end
