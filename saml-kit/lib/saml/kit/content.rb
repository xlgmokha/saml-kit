module Saml
  module Kit
    class Content
      BASE64_FORMAT = %r(\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z)

      def self.encode_raw_saml(xml)
        encode(deflate(xml))
      end

      def self.decode_raw_saml(xml)
        return xml unless base64_encoded?(xml)

        decoded = decode(xml)
        begin
          inflate(decoded)
        rescue
          decoded
        end
      end

      def url_encode(xml)
        CGI.escape(Base64.encode64(deflate(xml)))
      end

      def self.decode(value)
        Base64.decode64(value)
      end

      def self.encode(value)
        Base64.encode64(value).gsub(/\n/, '')
      end

      def self.base64_encoded?(value)
        !!value.gsub(/[\r\n]|\\r|\\n|\s/, "").match(BASE64_FORMAT)
      end

      def self.inflate(value)
        Zlib::Inflate.new.inflate(value)
      end

      def self.deflate(value, level: Zlib::BEST_COMPRESSION)
        Zlib::Deflate.deflate(value, level)
      end
    end
  end
end
