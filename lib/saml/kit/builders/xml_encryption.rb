module Saml
  module Kit
    module Builders
      class XmlEncryption
        attr_reader :public_key
        attr_reader :key, :iv, :encrypted

        def initialize(raw_xml, public_key)
          @public_key = public_key
          cipher = OpenSSL::Cipher.new('AES-256-CBC')
          cipher.encrypt
          @key = cipher.random_key
          @iv = cipher.random_iv
          @encrypted = cipher.update(raw_xml) + cipher.final
        end
      end
    end
  end
end

