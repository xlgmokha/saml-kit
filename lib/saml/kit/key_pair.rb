module Saml
  module Kit
    class KeyPair
      attr_reader :certificate, :private_key, :use

      def initialize(certificate, private_key, password, use)
        @use = use
        @certificate = Saml::Kit::Certificate.new(certificate, use: use)
        @private_key = OpenSSL::PKey::RSA.new(private_key, password)
      end

      def for?(use)
        @use == use
      end
    end
  end
end
