require 'saml/kit/crypto/oaep_cipher'
require 'saml/kit/crypto/rsa_cipher'
require 'saml/kit/crypto/simple_cipher'
require 'saml/kit/crypto/unknown_cipher'

module Saml
  module Kit
    module Crypto
      def self.decryptor_for(algorithm, key)
        decryptors = [ SimpleCipher, RsaCipher, OaepCipher, UnknownCipher ]
        decryptors.find { |x| x.matches?(algorithm) }.new(algorithm, key)
      end
    end
  end
end
