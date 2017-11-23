module Saml
  module Kit
    class Cryptography
      attr_reader :private_key

      def initialize(private_key = Saml::Kit.configuration.encryption_private_key)
        @private_key = private_key
      end

      #{
        #"EncryptedData"=> {
          #"xmlns:xenc"=>"http://www.w3.org/2001/04/xmlenc#",
          #"xmlns:dsig"=>"http://www.w3.org/2000/09/xmldsig#",
          #"Type"=>"http://www.w3.org/2001/04/xmlenc#Element",
          #"EncryptionMethod"=> { "Algorithm"=>"http://www.w3.org/2001/04/xmlenc#aes128-cbc" },
          #"KeyInfo"=> {
            #"xmlns:dsig"=>"http://www.w3.org/2000/09/xmldsig#",
            #"EncryptedKey"=>
            #{
              #"EncryptionMethod"=>{ "Algorithm"=>"http://www.w3.org/2001/04/xmlenc#rsa-1_5" },
              #"CipherData"=>{ "CipherValue"=>"" }
            #}
          #},
          #"CipherData"=>{ "CipherValue"=>"" }
        #}
      #}
      def decrypt(data)
        encrypt_data = data['EncryptedData']
        symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
        node = Base64.decode64(encrypt_data["CipherData"]["CipherValue"])
        retrieve_plaintext(node, symmetric_key, encrypt_data["EncryptionMethod"]['Algorithm'])
      end

      private

      def retrieve_symmetric_key(encrypted_data, private_key)
        encrypted_key = encrypted_data['KeyInfo']['EncryptedKey']
        cipher_text = Base64.decode64(encrypted_key['CipherData']['CipherValue'])
        retrieve_plaintext(cipher_text, private_key, encrypted_key["EncryptionMethod"]['Algorithm'])
      end

      def retrieve_plaintext(cipher_text, symmetric_key, algorithm)
        case algorithm
          when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
          when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
        end

        if cipher
          iv_len = cipher.iv_len
          data = cipher_text[iv_len..-1]
          cipher.padding, cipher.key, cipher.iv = 0, symmetric_key, cipher_text[0..iv_len-1]
          assertion_plaintext = cipher.update(data)
          assertion_plaintext << cipher.final
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
