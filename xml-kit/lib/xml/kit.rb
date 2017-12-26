require "base64"
require "logger"
require "openssl"

require "xml/kit/crypto"
require "xml/kit/id"
require "xml/kit/version"
require "xml/kit/xml_decryption"

module Xml
  module Kit
    class << self
      def logger
        @logger ||= Logger.new(STDOUT)
      end

      def logger=(logger)
        @logger = logger
      end
    end
  end
end
