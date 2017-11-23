require 'spec_helper'

RSpec.describe Saml::Kit::Cryptography do
  describe "#decrypt" do
    #let(:secret) { FFaker::Movie.title }
    let(:secret) { "SECRET" }
    let(:password) { FFaker::Movie.title }

    it 'decrypts the data' do
      certificate_pem, private_key_pem = Saml::Kit::SelfSignedCertificate.new(password).create
      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
      private_key = OpenSSL::PKey::RSA.new(private_key_pem, password)

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      encrypted = cipher.update(secret) + cipher.final

      data = {
        "EncryptedData"=> {
          "xmlns:xenc"=>"http://www.w3.org/2001/04/xmlenc#",
          "xmlns:dsig"=>"http://www.w3.org/2000/09/xmldsig#",
          "Type"=>"http://www.w3.org/2001/04/xmlenc#Element",
          "EncryptionMethod"=> { 
            "Algorithm"=>"http://www.w3.org/2001/04/xmlenc#aes128-cbc"
          },
          "KeyInfo"=> {
            "xmlns:dsig"=>"http://www.w3.org/2000/09/xmldsig#",
            "EncryptedKey"=> {
              "EncryptionMethod"=>{ 
                "Algorithm"=>"http://www.w3.org/2001/04/xmlenc#rsa-1_5"
              },
              "CipherData"=>{
                "CipherValue"=> Base64.encode64(public_key.public_encrypt(key))
              }
            }
          },
          "CipherData"=>{
            "CipherValue"=> Base64.encode64(iv + encrypted)
          }
        }
      }
      subject = described_class.new(private_key)
      decrypted = subject.decrypt(data)
      expect(decrypted.strip).to eql(secret)
    end
  end
end
