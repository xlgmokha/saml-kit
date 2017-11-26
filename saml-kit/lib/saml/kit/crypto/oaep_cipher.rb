module Saml
  module Kit
    module Crypto
      class OaepCipher
        def initialize(algorithm, key)
          @key = key
        end

        def self.matches?(algorithm)
          'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' == algorithm
        end

        def decrypt(cipher_text)
          @key.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        end
      end
    end
  end
end
