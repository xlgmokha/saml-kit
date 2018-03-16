# frozen_string_literal: true

module Saml
  module Kit
    # This class is a base class for SAML documents.
    class Document
      include ActiveModel::Validations
      include XsdValidatable
      include Translatable
      include Trustable
      include Buildable
      PROTOCOL_XSD = File.expand_path(
        './xsd/saml-schema-protocol-2.0.xsd', File.dirname(__FILE__)
      ).freeze
      NAMESPACES = {
        "NameFormat": ::Saml::Kit::Namespaces::ATTR_SPLAT,
        "ds": ::Xml::Kit::Namespaces::XMLDSIG,
        "md": ::Saml::Kit::Namespaces::METADATA,
        "saml": ::Saml::Kit::Namespaces::ASSERTION,
        "samlp": ::Saml::Kit::Namespaces::PROTOCOL,
        'xmlenc' => ::Xml::Kit::Namespaces::XMLENC,
      }.freeze
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

      # Returns the SAML document returned as a Hash.
      def to_h
        @to_h ||= Hash.from_xml(content) || {}
      end

      # Returns the SAML document as an XML string.
      #
      # @param pretty [Boolean] formats the xml or returns the raw xml.
      def to_xml(pretty: nil)
        pretty ? to_nokogiri.to_xml(indent: 2) : to_s
      end

      # Returns the SAML document as an XHTML string.
      # This is useful for rendering in a web page.
      def to_xhtml
        Nokogiri::XML(to_xml, &:noblanks).to_xhtml
      end

      # @!visibility private
      def to_nokogiri
        @to_nokogiri ||= Nokogiri::XML(to_s)
      end

      # @!visibility private
      def at_xpath(xpath)
        to_nokogiri.at_xpath(xpath, NAMESPACES)
      end

      # @!visibility private
      def search(xpath)
        to_nokogiri.search(xpath, NAMESPACES)
      end

      def to_s
        content
      end

      class << self
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
          namespaces = { "samlp": ::Saml::Kit::Namespaces::PROTOCOL }
          document = Nokogiri::XML(xml)
          element = document.at_xpath(XPATH, namespaces)
          constructor = {
            'AuthnRequest' => Saml::Kit::AuthenticationRequest,
            'LogoutRequest' => Saml::Kit::LogoutRequest,
            'LogoutResponse' => Saml::Kit::LogoutResponse,
            'Response' => Saml::Kit::Response,
          }[element.name] || InvalidDocument
          constructor.new(xml, configuration: configuration)
        rescue StandardError => error
          Saml::Kit.logger.error(error)
          InvalidDocument.new(xml, configuration: configuration)
        end

        # @!visibility private
        def builder_class # :nodoc:
          case name
          when Saml::Kit::Response.to_s
            Saml::Kit::Builders::Response
          when Saml::Kit::LogoutResponse.to_s
            Saml::Kit::Builders::LogoutResponse
          when Saml::Kit::AuthenticationRequest.to_s
            Saml::Kit::Builders::AuthenticationRequest
          when Saml::Kit::LogoutRequest.to_s
            Saml::Kit::Builders::LogoutRequest
          else
            raise ArgumentError, "Unknown SAML Document #{name}"
          end
        end
      end

      private

      attr_reader :content, :configuration

      def must_match_xsd
        matches_xsd?(PROTOCOL_XSD)
      end

      def must_be_expected_type
        errors[:base] << error_message(:invalid) unless expected_type?
      end

      def expected_type?
        at_xpath("./samlp:#{name}").present?
      end

      def must_be_valid_version
        return unless expected_type?
        return if version == '2.0'
        errors[:version] << error_message(:invalid_version)
      end
    end
  end
end
