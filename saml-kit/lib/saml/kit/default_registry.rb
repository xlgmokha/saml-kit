module Saml
  module Kit
    class DefaultRegistry
      def initialize(items = {})
        @items = items
      end

      def register(metadata)
        @items[metadata.entity_id] = metadata
      end

      def register_url(url, verify_ssl: true)
        content = HttpApi.new(url, verify_ssl: verify_ssl).get
        register(Saml::Kit::Metadata.from(content))
      end

      def metadata_for(entity_id)
        @items[entity_id]
      end

      class HttpApi
        attr_reader :uri, :verify_ssl

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

        def http
          http = Net::HTTP.new(uri.host, uri.port)
          http.read_timeout = 30
          http.use_ssl = uri.is_a?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless verify_ssl
          http
        end
      end
    end
  end
end
