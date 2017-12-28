module Saml
  module Kit
    # This class represents the main configuration that is use for generating SAML documents.
    #
    #   Saml::Kit::Configuration.new do |config|
    #     config.issuer = "com:saml:kit"
    #     config.signature_method = :SHA256
    #     config.digest_method = :SHA256
    #     config.registry = Saml::Kit::DefaultRegistry.new
    #     config.session_timeout = 30.minutes
    #     config.logger = Rails.logger
    #   end
    #
    #   To specify global configuration it is best to do this in an initializer
    #   that runs at the start of the program.
    #
    #   Saml::Kit.configure do |configuration|
    #     configuration.issuer = "https://www.example.com/saml/metadata"
    #     configuration.generate_key_pair_for(use: :signing)
    #     configuration.add_key_pair(ENV["X509_CERTIFICATE"], ENV["PRIVATE_KEY"], passphrase: ENV['PRIVATE_KEY_PASSPHRASE'], use: :encryption)
    #   end
    class Configuration
      # The issuer or entity_id to use.
      attr_accessor :issuer
      # The signature method to use when generating signatures (See {Saml::Kit::Builders::XmlSignature::SIGNATURE_METHODS})
      attr_accessor :signature_method
      # The digest method to use when generating signatures (See {Saml::Kit::Builders::XmlSignature::DIGEST_METHODS})
      attr_accessor :digest_method
      # The metadata registry to use for searching for metadata associated with an issuer.
      attr_accessor :registry
      # The session timeout to use when generating an Assertion.
      attr_accessor :session_timeout
      # The logger to write log messages to.
      attr_accessor :logger
      # The total allowable clock drift for session timeout validation.
      attr_accessor :clock_drift

      def initialize # :yields configuration
        @clock_drift = 30.seconds
        @digest_method = :SHA256
        @key_pairs = []
        @logger = Logger.new(STDOUT)
        @registry = DefaultRegistry.new
        @session_timeout = 3.hours
        @signature_method = :SHA256
        yield self if block_given?
      end

      # Add a key pair that can be used for either signing or encryption.
      #
      # @param certificate [String] the x509 certificate with public key.
      # @param private_key [String] the plain text private key.
      # @param passphrase [String] the password to decrypt the private key.
      # @param use [Symbol] the type of key pair, `:signing` or `:encryption`
      def add_key_pair(certificate, private_key, passphrase: '', use: :signing)
        @key_pairs.push(::Xml::Kit::KeyPair.new(certificate, private_key, passphrase, use.to_sym))
      end

      # Generates a unique key pair that can be used for signing or encryption.
      #
      # @param use [Symbol] the type of key pair, `:signing` or `:encryption`
      # @param passphrase [String] the private key passphrase to use.
      def generate_key_pair_for(use:, passphrase: SecureRandom.uuid)
        certificate, private_key = ::Xml::Kit::SelfSignedCertificate.new(passphrase).create
        add_key_pair(certificate, private_key, passphrase: passphrase, use: use)
      end

      # Return each key pair for a specific use.
      #
      # @param use [Symbol] the type of key pair to return `nil`, `:signing` or `:encryption`
      def key_pairs(use: nil)
        use.present? ? @key_pairs.find_all { |x| x.for?(use) } : @key_pairs
      end

      # Return each certificate for a specific use.
      #
      # @param use [Symbol] the type of key pair to return `nil`, `:signing` or `:encryption`
      def certificates(use: nil)
        key_pairs(use: use).flat_map(&:certificate)
      end

      # Return each private for a specific use.
      #
      # @param use [Symbol] the type of key pair to return `nil`, `:signing` or `:encryption`
      def private_keys(use: :signing)
        key_pairs(use: use).flat_map(&:private_key)
      end

      # @deprecated Use {#certificates} instead of this method.
      def encryption_certificate
        Saml::Kit.deprecate("encryption_certificate is deprecated. Use certificates(use: :encryption) instead")
        certificates(use: :encryption).last
      end

      # @deprecated Use {#private_keys} instead of this method.
      def signing_private_key
        Saml::Kit.deprecate("signing_private_key is deprecated. Use private_keys(use: :signing) instead")
        private_keys(use: :signing).last
      end

      # @deprecated Use {#private_keys} instead of this method.
      def encryption_private_key
        Saml::Kit.deprecate("encryption_private_key is deprecated. Use private_keys(use: :encryption) instead")
        private_keys(use: :encryption).last
      end

      # Returns true if there is at least one signing certificate registered.
      def sign?
        certificates(use: :signing).any?
      end
    end
  end
end
