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
        self.class.to_x509(value)
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

      def to_h
        { use: @use, x509: @value }
      end

      def inspect
        to_h.inspect
      end

      def self.to_x509(value)
        OpenSSL::X509::Certificate.new(Base64.decode64(value))
      rescue OpenSSL::X509::CertificateError => error
        Saml::Kit.logger.warn(error)
        OpenSSL::X509::Certificate.new(value)
      end
    end
  end
end
