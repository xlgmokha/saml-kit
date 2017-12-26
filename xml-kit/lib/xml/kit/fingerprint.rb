module Xml
  module Kit
    # This generates a fingerprint for an X509 Certificate.
    #
    #   certificate, _ = Saml::Kit::SelfSignedCertificate.new("password").create
    #
    #   puts Saml::Kit::Fingerprint.new(certificate).to_s
    #   # B7:AB:DC:BD:4D:23:58:65:FD:1A:99:0C:5F:89:EA:87:AD:F1:D7:83:34:7A:E9:E4:88:12:DD:46:1F:38:05:93
    #
    # {include:file:spec/saml/fingerprint_spec.rb}
    class Fingerprint
      # The OpenSSL::X509::Certificate
      attr_reader :x509

      def initialize(raw_certificate)
        @x509 = Certificate.to_x509(raw_certificate)
      end

      # Generates a formatted fingerprint using the specified hash algorithm.
      #
      # @param algorithm [OpenSSL::Digest] the openssl algorithm to use `OpenSSL::Digest::SHA256`, `OpenSSL::Digest::SHA1`.
      # @return [String] in the format of `"BF:ED:C5:F1:6C:AB:F5:B2:15:1F:BF:BD:7D:68:1A:F9:A5:4E:4C:19:30:BC:6D:25:B1:8E:98:D4:23:FD:B4:09"`
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
