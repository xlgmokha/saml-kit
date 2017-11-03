module Saml
  module Kit
    class DefaultRegistry
      def registered?(issuer, fingerprint)
        issuer.present? && fingerprint.algorithm(OpenSSL::Digest::SHA256).present?
      end
    end
  end
end
