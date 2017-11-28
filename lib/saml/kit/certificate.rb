module Saml
  module Kit
    class Certificate
      attr_reader :value, :use

      def initialize(value, use:)
        @value = value
        @use = use.downcase.to_sym
      end

      def fingerprint
        Fingerprint.new(value)
      end

      def for?(use)
        self.use == use.to_sym
      end

      def encryption?
        :encryption == use
      end

      def signing?
        :signing == use
      end

      def x509
        OpenSSL::X509::Certificate.new(Base64.decode64(value))
      end

      def public_key
        x509.public_key
      end

      def ==(other)
        self.to_s == other.to_s
      end

      def eql?(other)
        self == other
      end

      def hash
        value.hash
      end

      def to_s
        value
      end
    end
  end
end
