# frozen_string_literal: true

module Saml
  module Kit
    module Serializable
      # Base 64 decodes the value.
      #
      # @param value [String] the string to base 64 decode.
      def decode(value)
        Base64.decode64(value)
      end

      # Base 64 encodes the value.
      #
      # @param value [String] the string to base 64 encode.
      def encode(value)
        Base64.strict_encode64(value)
      end

      # Inflates the value using zlib decompression.
      #
      # @param value [String] the value to inflate.
      def inflate(value)
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        inflater.inflate(value)
      end

      # Deflate the value and drop the header and checksum as per the SAML spec.
      # https://en.wikipedia.org/wiki/SAML_2.0#HTTP_Redirect_Binding
      #
      # @param value [String] the value to deflate.
      # @param level [Integer] the level of compression.
      def deflate(value, level: Zlib::BEST_COMPRESSION)
        Zlib::Deflate.deflate(value, level)[2..-5]
      end

      # URL unescape a value
      #
      # @param value [String] the value to unescape.
      def unescape(value)
        CGI.unescape(value)
      end

      # URL escape a value
      #
      # @param value [String] the value to escape.
      def escape(value)
        CGI.escape(value)
      end
    end
  end
end
