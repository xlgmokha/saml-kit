# frozen_string_literal: true

module Saml
  module Kit
    # This class is a base class for SAML documents.
    class Document
      include ActiveModel::Validations
      include Buildable
      include Translatable
      include Trustable
      include XmlParseable
      include XsdValidatable

      attr_accessor :registry
      attr_reader :name
      validates_presence_of :content
      validates_presence_of :id
      validate :must_match_xsd
      validate :must_be_expected_type
      validate :must_be_valid_version

      def initialize(xml, name:, configuration: Saml::Kit.configuration)
        @configuration = configuration
        @registry = configuration.registry
        @content = xml
        @name = name
      end

      # Returns the ID for the SAML document.
      def id
        at_xpath('./*/@ID').try(:value)
      end

      # Returns the Issuer for the SAML document.
      def issuer
        at_xpath('./*/saml:Issuer').try(:text)
      end

      # Returns the Version of the SAML document.
      def version
        at_xpath('./*/@Version').try(:value)
      end

      # Returns the Destination of the SAML document.
      def destination
        at_xpath('./*/@Destination').try(:value)
      end

      # Returns the Destination of the SAML document.
      def issue_instant
        Time.parse(at_xpath('./*/@IssueInstant').try(:value))
      end

      class << self
        CONSTRUCTORS = {
          'AuthnRequest' => -> { Saml::Kit::AuthenticationRequest },
          'LogoutRequest' => -> { Saml::Kit::LogoutRequest },
          'LogoutResponse' => -> { Saml::Kit::LogoutResponse },
          'Response' => -> { Saml::Kit::Response },
        }.freeze
        XPATH = [
          '/samlp:AuthnRequest',
          '/samlp:LogoutRequest',
          '/samlp:LogoutResponse',
          '/samlp:Response',
        ].join('|')

        # Returns the raw xml as a Saml::Kit SAML document.
        #
        # @param xml [String] the raw xml string.
        # @param configuration [Saml::Kit::Configuration] configuration to use
        # for unpacking the document.
        def to_saml_document(xml, configuration: Saml::Kit.configuration)
          namespaces = { samlp: Namespaces::PROTOCOL }
          element = Nokogiri::XML(xml).at_xpath(XPATH, namespaces)
          constructor = CONSTRUCTORS[element.name].try(:call) || InvalidDocument
          constructor.new(xml, configuration: configuration)
        rescue StandardError => error
          Saml::Kit.logger.error(error)
          InvalidDocument.new(xml, configuration: configuration)
        end

        # @!visibility private
        def builder_class # :nodoc:
          {
            Assertion.to_s => Saml::Kit::Builders::Assertion,
            AuthenticationRequest.to_s => Saml::Kit::Builders::AuthenticationRequest,
            LogoutRequest.to_s => Saml::Kit::Builders::LogoutRequest,
            LogoutResponse.to_s => Saml::Kit::Builders::LogoutResponse,
            Response.to_s => Saml::Kit::Builders::Response,
          }[name] || (raise ArgumentError, "Unknown SAML Document #{name}")
        end
      end

      private

      attr_reader :content, :configuration

      def must_match_xsd
        matches_xsd?(PROTOCOL_XSD)
      end

      def must_be_expected_type
        errors.add(:base, error_message(:invalid)) unless expected_type?
      end

      def expected_type?
        at_xpath("./samlp:#{name}").present?
      end

      def must_be_valid_version
        return unless expected_type?
        return if version == '2.0'

        errors.add(:version, error_message(:invalid_version))
      end
    end
  end
end
