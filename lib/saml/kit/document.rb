module Saml
  module Kit
    class Document
      PROTOCOL_XSD = File.expand_path("./xsd/saml-schema-protocol-2.0.xsd", File.dirname(__FILE__)).freeze
      NAMESPACES = {
        "NameFormat": ::Saml::Kit::Namespaces::ATTR_SPLAT,
        "ds": ::Xml::Kit::Namespaces::XMLDSIG,
        "md": ::Saml::Kit::Namespaces::METADATA,
        "saml": ::Saml::Kit::Namespaces::ASSERTION,
        "samlp": ::Saml::Kit::Namespaces::PROTOCOL,
      }.freeze
      include ActiveModel::Validations
      include XsdValidatable
      include Translatable
      include Trustable
      include Buildable
      validates_presence_of :content
      validates_presence_of :id
      validate :must_match_xsd
      validate :must_be_expected_type
      validate :must_be_valid_version

      def initialize(xml, name:, configuration: Saml::Kit.configuration)
        @configuration = configuration
        @content = xml
        @name = name
      end

      # Returns the ID for the SAML document.
      def id
        root.fetch('ID', nil)
      end

      # Returns the Issuer for the SAML document.
      def issuer
        root.fetch('Issuer', nil)
      end

      # Returns the Version of the SAML document.
      def version
        root.fetch('Version', {})
      end

      # Returns the Destination of the SAML document.
      def destination
        root.fetch('Destination', nil)
      end

      # Returns the Destination of the SAML document.
      def issue_instant
        Time.parse(root['IssueInstant'])
      end

      # Returns the SAML document returned as a Hash.
      def to_h
        @xml_hash ||= Hash.from_xml(content) || {}
      end

      # Returns the SAML document as an XML string.
      #
      # @param pretty [Boolean] formats the xml or returns the raw xml.
      def to_xml(pretty: false)
        pretty ? Nokogiri::XML(content).to_xml(indent: 2) : content
      end

      # Returns the SAML document as an XHTML string. 
      # This is useful for rendering in a web page.
      def to_xhtml
        Nokogiri::XML(content, &:noblanks).to_xhtml
      end

      def to_s
        to_xml
      end

      class << self
        XPATH = [
          "/samlp:AuthnRequest",
          "/samlp:LogoutRequest",
          "/samlp:LogoutResponse",
          "/samlp:Response",
        ].join("|")

        # Returns the raw xml as a Saml::Kit SAML document.
        #
        # @param xml [String] the raw xml string.
        # @param configuration [Saml::Kit::Configuration] the configuration to use for unpacking the document.
        def to_saml_document(xml, configuration: Saml::Kit.configuration)
          xml_document = ::Xml::Kit::Xml.new(xml, namespaces: {
            "samlp": ::Saml::Kit::Namespaces::PROTOCOL
          })
          constructor = {
            "AuthnRequest" => Saml::Kit::AuthenticationRequest,
            "LogoutRequest" => Saml::Kit::LogoutRequest,
            "LogoutResponse" => Saml::Kit::LogoutResponse,
            "Response" => Saml::Kit::Response,
          }[xml_document.find_by(XPATH).name] || InvalidDocument
          constructor.new(xml, configuration: configuration)
        rescue => error
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
            raise ArgumentError.new("Unknown SAML Document #{name}")
          end
        end
      end

      private

      attr_reader :content, :name, :configuration

      def root
        to_h.fetch(name, {})
      end

      def must_match_xsd
        matches_xsd?(PROTOCOL_XSD)
      end

      def must_be_expected_type
        errors[:base] << error_message(:invalid) unless expected_type?
      end

      def expected_type?
        to_h[name].present?
      end

      def must_be_valid_version
        return unless expected_type?
        return if "2.0" == version
        errors[:version] << error_message(:invalid_version)
      end
    end
  end
end
