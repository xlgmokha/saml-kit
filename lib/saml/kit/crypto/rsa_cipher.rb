module Saml
  module Kit
    module Crypto
      class RsaCipher
        ALGORITHMS = {
          'http://www.w3.org/2001/04/xmlenc#rsa-1_5' => true,
        }

        def initialize(algorithm, key)
          @key = key
        end

        def self.matches?(algorithm)
          ALGORITHMS[algorithm]
        end

        def decrypt(cipher_text)
          @key.private_decrypt(cipher_text)
        end
      end
    end
  end
end
