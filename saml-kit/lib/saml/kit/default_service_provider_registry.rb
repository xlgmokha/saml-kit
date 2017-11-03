module Saml
  module Kit
    class DefaultServiceProviderRegistry
      def registered?(issuer, fingerprint)
        issuer.present? && fingerprint.algorithm(OpenSSL::Digest::SHA256).present?
      end
    end
  end
end
