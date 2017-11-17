module Saml
  module Kit
    class Content
      def self.deserialize(xml)
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
