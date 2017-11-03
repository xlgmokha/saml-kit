module Saml
  module Kit
    class Fingerprint
      attr_reader :x509

      def initialize(raw_certificate)
        @x509 = OpenSSL::X509::Certificate.new(raw_certificate)
      rescue OpenSSL::X509::CertificateError
        @x509 = OpenSSL::X509::Certificate.new(Base64.decode64(raw_certificate))
      end

      def algorithm(algorithm)
        pretty_fingerprint(algorithm.new.hexdigest(x509.to_der))
      end

      def ==(other)
        self.to_s == other.to_s
      end

      def eql?(other)
        self == other
      end

      def hash
        to_s.hash
      end

      def to_s
        algorithm(OpenSSL::Digest::SHA256)
      end

      private

      def pretty_fingerprint(fingerprint)
        fingerprint.upcase.scan(/../).join(":")
      end
    end
  end
end
