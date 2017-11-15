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
        rescue => error
          Saml::Kit.logger.error(error)
          decoded
        end
      end

      def self.decode(value)
        Base64.decode64(value)
      end

      def self.encode(value)
        Base64.strict_encode64(value)
      end

      def self.base64_encoded?(value)
        !!value.gsub(/[\r\n]|\\r|\\n|\s/, "").match(BASE64_FORMAT)
      end

      def self.inflate(value)
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        inflater.inflate(value)
      end

      def self.deflate(value, level: Zlib::BEST_COMPRESSION)
        Zlib::Deflate.deflate(value, level)[2..-5]
      end
    end
  end
end
