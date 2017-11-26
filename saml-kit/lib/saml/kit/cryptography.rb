module Saml
  module Kit
    class Cryptography
      attr_reader :private_key

      def initialize(private_key = Saml::Kit.configuration.encryption_private_key)
        @private_key = private_key
      end

      def decrypt(data)
        encrypt_data = data['EncryptedData']
        symmetric_key = symmetric_key_from(encrypt_data)
        cipher_text = Base64.decode64(encrypt_data["CipherData"]["CipherValue"])
        to_plaintext(cipher_text, symmetric_key, encrypt_data["EncryptionMethod"]['Algorithm'])
      end

      private

      def symmetric_key_from(encrypted_data)
        encrypted_key = encrypted_data['KeyInfo']['EncryptedKey']
        cipher_text = Base64.decode64(encrypted_key['CipherData']['CipherValue'])
        to_plaintext(cipher_text, private_key, encrypted_key["EncryptionMethod"]['Algorithm'])
      end

      def to_plaintext(cipher_text, symmetric_key, algorithm)
        return decryptor_for(algorithm, symmetric_key).decrypt(cipher_text)
      end

      def decryptor_for(algorithm, key)
        decryptors = [ SimpleCipher, RsaCipher, OaepCipher, UnknownCipher ]
        decryptors.find { |x| x.matches?(algorithm) }.new(algorithm, key)
      end

      class SimpleCipher
        ALGORITHMS = {
          'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' => true,
          'http://www.w3.org/2001/04/xmlenc#aes128-cbc' => true,
          'http://www.w3.org/2001/04/xmlenc#aes192-cbc' => true,
          'http://www.w3.org/2001/04/xmlenc#aes256-cbc' => true,
        }

        def initialize(algorithm, key)
          @key = key
          @cipher = case algorithm
          when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
            OpenSSL::Cipher.new('DES-EDE3-CBC')
          when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            OpenSSL::Cipher.new('AES-128-CBC')
          when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
            OpenSSL::Cipher.new('AES-192-CBC')
          when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
            OpenSSL::Cipher.new('AES-256-CBC')
          end
        end

        def self.matches?(algorithm)
          ALGORITHMS[algorithm]
        end

        def decrypt(cipher_text)
          @cipher.decrypt
          iv = cipher_text[0..@cipher.iv_len-1]
          data = cipher_text[@cipher.iv_len..-1]
          #@cipher.padding = 0
          @cipher.key = @key
          @cipher.iv = iv

          Saml::Kit.logger.debug ['-key', @key].inspect
          Saml::Kit.logger.debug ['-iv', iv].inspect

          @cipher.update(data) + @cipher.final
        end
      end

      class RsaCipher
        def initialize(algorithm, key)
          @key = key
        end

        def self.matches?(algorithm)
          'http://www.w3.org/2001/04/xmlenc#rsa-1_5' == algorithm
        end

        def decrypt(cipher_text)
          @key.private_decrypt(cipher_text)
        end
      end

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
