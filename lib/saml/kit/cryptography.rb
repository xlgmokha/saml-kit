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
        return Crypto.decryptor_for(algorithm, symmetric_key).decrypt(cipher_text)
      end
    end
  end
end
