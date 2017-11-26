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
        case algorithm
        when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
          cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
          cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
          cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
          cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
        when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
          rsa = symmetric_key
        when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
          oaep = symmetric_key
        end

        if cipher
          iv = cipher_text[0..cipher.iv_len-1]
          data = cipher_text[cipher.iv_len..-1]
          #cipher.padding = 0
          cipher.key = symmetric_key
          cipher.iv = iv

          Saml::Kit.logger.debug ['-key', symmetric_key].inspect
          Saml::Kit.logger.debug ['-iv', iv].inspect

          cipher.update(data) + cipher.final
        elsif rsa
          rsa.private_decrypt(cipher_text)
        elsif oaep
          oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          cipher_text
        end
      end
    end
  end
end
