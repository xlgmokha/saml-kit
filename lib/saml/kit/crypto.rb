require 'saml/kit/crypto/oaep_cipher'
require 'saml/kit/crypto/rsa_cipher'
require 'saml/kit/crypto/simple_cipher'
require 'saml/kit/crypto/unknown_cipher'

module Saml
  module Kit
    module Crypto
      DECRYPTORS = [ SimpleCipher, RsaCipher, OaepCipher, UnknownCipher ]

      def self.decryptor_for(algorithm, key)
        DECRYPTORS.find { |x| x.matches?(algorithm) }.new(algorithm, key)
      end
    end
  end
end
