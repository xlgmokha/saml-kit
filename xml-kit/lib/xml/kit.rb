require "active_model"
require "active_support/core_ext/numeric/time"
require "base64"
require "builder"
require "logger"
require "nokogiri"
require "openssl"
require "tilt"
require "xmldsig"

require "xml/kit/namespaces"

require "xml/kit/builders/encryption"
require "xml/kit/builders/signature"
require "xml/kit/certificate"
require "xml/kit/crypto"
require "xml/kit/decryption"
require "xml/kit/document"
require "xml/kit/fingerprint"
require "xml/kit/id"
require "xml/kit/key_pair"
require "xml/kit/self_signed_certificate"
require "xml/kit/signatures"
require "xml/kit/templatable"
require "xml/kit/template"
require "xml/kit/version"

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
