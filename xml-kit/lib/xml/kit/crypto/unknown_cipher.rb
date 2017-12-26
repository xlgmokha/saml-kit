module Xml
  module Kit
    module Crypto
      class UnknownCipher
        def initialize(algorithm, key)
        end

        def self.matches?(algorithm)
          true
        end

        def decrypt(cipher_text)
          cipher_text
        end
      end
    end
  end
end
