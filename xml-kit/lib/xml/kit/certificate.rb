module Xml
  module Kit
    # {include:file:spec/xml/certificate_spec.rb}
    class Certificate
      BEGIN_CERT=/-----BEGIN CERTIFICATE-----/
      END_CERT=/-----END CERTIFICATE-----/
      # The use can be `:signing` or `:encryption`
      attr_reader :use

      def initialize(value, use:)
        @value = value
        @use = use.downcase.to_sym
      end

      # @return [Xml::Kit::Fingerprint] the certificate fingerprint.
      def fingerprint
        Fingerprint.new(value)
      end

      # Returns true if this certificate is for the specified use.
      #
      # @param use [Symbol] `:signing` or `:encryption`.
      # @return [Boolean] true or false.
      def for?(use)
        self.use == use.to_sym
      end

      # Returns true if this certificate is used for encryption.
      #
      # return [Boolean] true or false.
      def encryption?
        for?(:encryption)
      end

      # Returns true if this certificate is used for signing.
      #
      # return [Boolean] true or false.
      def signing?
        for?(:signing)
      end

      # Returns the x509 form.
      #
      # return [OpenSSL::X509::Certificate] the OpenSSL equivalent.
      def x509
        self.class.to_x509(value)
      end

      # Returns the public key.
      #
      # @return [OpenSSL::PKey::RSA] the RSA public key.
      def public_key
        x509.public_key
      end

      def ==(other)
        self.fingerprint == other.fingerprint
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
        { use: @use, fingerprint: fingerprint.to_s }
      end

      def inspect
        to_h.inspect
      end

      def stripped
        value.to_s.gsub(BEGIN_CERT, '').gsub(END_CERT, '').gsub(/\n/, '')
      end

      def self.to_x509(value)
        OpenSSL::X509::Certificate.new(Base64.decode64(value))
      rescue OpenSSL::X509::CertificateError => error
        ::Xml::Kit.logger.warn(error)
        OpenSSL::X509::Certificate.new(value)
      end

      private

      attr_reader :value
    end
  end
end
