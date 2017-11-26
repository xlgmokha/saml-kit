module Saml
  module Kit
    module Crypto
      class SimpleCipher
        ALGORITHMS = {
          'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' => true,
          'http://www.w3.org/2001/04/xmlenc#aes128-cbc' => true,
          'http://www.w3.org/2001/04/xmlenc#aes192-cbc' => true,
          'http://www.w3.org/2001/04/xmlenc#aes256-cbc' => true,
        }

        def initialize(algorithm, key)
          @algorithm = algorithm
          @key = key
        end

        def self.matches?(algorithm)
          ALGORITHMS[algorithm]
        end

        def decrypt(cipher_text)
          cipher = cipher_for(@algorithm)
          cipher.decrypt
          iv = cipher_text[0..cipher.iv_len-1]
          data = cipher_text[cipher.iv_len..-1]
          #cipher.padding = 0
          cipher.key = @key
          cipher.iv = iv

          Saml::Kit.logger.debug ['-key', @key].inspect
          Saml::Kit.logger.debug ['-iv', iv].inspect

          cipher.update(data) + cipher.final
        end

        private

        def cipher_for(algorithm)
          name = case algorithm
                 when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
                   'DES-EDE3-CBC'
                 when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
                   'AES-128-CBC'
                 when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
                   'AES-192-CBC'
                 when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
                   'AES-256-CBC'
                 end
          OpenSSL::Cipher.new(name)
        end
      end
    end
  end
end
