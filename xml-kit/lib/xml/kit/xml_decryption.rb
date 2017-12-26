module Xml
  module Kit
    # {include:file:spec/saml/xml_decryption_spec.rb}
    class XmlDecryption
      # The list of private keys to use to attempt to decrypt the document.
      attr_reader :private_keys

      def initialize(configuration: Saml::Kit.configuration)
        @private_keys = configuration.private_keys(use: :encryption)
      end

      # Decrypts an EncryptedData section of an XML document.
      #
      # @param data [Hash] the XML document converted to a [Hash] using Hash.from_xml.
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
        attempts = private_keys.count
        private_keys.each do |private_key|
          begin
            attempts -= 1
            return to_plaintext(cipher_text, private_key, encrypted_key["EncryptionMethod"]['Algorithm'])
          rescue OpenSSL::PKey::RSAError => error
            Saml::Kit.logger.error(error)
            raise if attempts.zero?
          end
        end
      end

      def to_plaintext(cipher_text, symmetric_key, algorithm)
        Crypto.decryptor_for(algorithm, symmetric_key).decrypt(cipher_text)
      end
    end
  end
end
