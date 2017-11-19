module Saml
  module Kit
    module Serializable
      def decode(value)
        Base64.decode64(value)
      end

      def encode(value)
        Base64.strict_encode64(value)
      end

      def inflate(value)
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        inflater.inflate(value)
      end

      def deflate(value, level: Zlib::BEST_COMPRESSION)
        Zlib::Deflate.deflate(value, level)[2..-5]
      end

      def unescape(value)
        CGI.unescape(value)
      end
    end
  end
end
