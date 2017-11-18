module Saml
  module Kit
    class Document
      PROTOCOL_XSD = File.expand_path("./xsd/saml-schema-protocol-2.0.xsd", File.dirname(__FILE__)).freeze
      include XsdValidatable
      include ActiveModel::Validations
      include Trustable

      attr_reader :content, :name, :query_string_parameter

      def initialize(xml, name:, query_string_parameter:)
        @query_string_parameter = query_string_parameter
        @content = xml
        @name = name
        @xml_hash = Hash.from_xml(xml) || {}
      end

      def id
        to_h.fetch(name, {}).fetch('ID', nil)
      end

      def issuer
        to_h.fetch(name, {}).fetch('Issuer', nil)
      end

      def version
        to_h.fetch(name, {}).fetch('Version', {})
      end

      def destination
        to_h.fetch(name, {}).fetch('Destination', nil)
      end

      def to_h
        @xml_hash
      end

      def to_xml
        content
      end

      def to_s
        to_xml
      end

      def self.to_saml_document(xml)
        hash = Hash.from_xml(xml)
        if hash['Response'].present?
          Response.new(xml)
        elsif hash['LogoutResponse'].present?
          LogoutResponse.new(xml)
        elsif hash['AuthnRequest'].present?
          AuthenticationRequest.new(xml)
        elsif hash['LogoutRequest'].present?
          LogoutRequest.new(xml)
        end
      rescue => error
        Saml::Kit.logger.error(error)
        InvalidDocument.new(xml)
      end
    end
  end
end
