module Saml
  module Kit
    class XmlDecryption
      attr_reader :private_key

      def initialize(configuration: Saml::Kit.configuration)
        @private_key = configuration.private_keys(use: :encryption).last
      end

      def decrypt(data)
        encrypted_data = data['EncryptedData']
        symmetric_key = symmetric_key_from(encrypted_data)
        cipher_text = Base64.decode64(encrypted_data["CipherData"]["CipherValue"])
        to_plaintext(cipher_text, symmetric_key, encrypted_data["EncryptionMethod"]['Algorithm'])
      end

      private

      def symmetric_key_from(encrypted_data)
        encrypted_key = encrypted_data['KeyInfo']['EncryptedKey']
        cipher_text = Base64.decode64(encrypted_key['CipherData']['CipherValue'])
        to_plaintext(cipher_text, private_key, encrypted_key["EncryptionMethod"]['Algorithm'])
      end

      def to_plaintext(cipher_text, symmetric_key, algorithm)
        Crypto.decryptor_for(algorithm, symmetric_key).decrypt(cipher_text)
      end
    end
  end
end
