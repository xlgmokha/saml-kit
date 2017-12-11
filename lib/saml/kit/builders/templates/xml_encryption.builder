xml.EncryptedAssertion xmlns: Saml::Kit::Namespaces::ASSERTION do
  xml.EncryptedData xmlns: Saml::Kit::Namespaces::XMLENC do
    xml.EncryptionMethod Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
    xml.KeyInfo xmlns: Saml::Kit::Namespaces::XMLDSIG do
      xml.EncryptedKey xmlns: Saml::Kit::Namespaces::XMLENC do
        xml.EncryptionMethod Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
        xml.CipherData do
          xml.CipherValue Base64.encode64(public_key.public_encrypt(key))
        end
      end
    end
    xml.CipherData do
      xml.CipherValue Base64.encode64(iv + encrypted)
    end
  end
end
