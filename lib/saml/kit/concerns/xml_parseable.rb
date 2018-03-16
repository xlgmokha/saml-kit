# frozen_string_literal: true

require 'saml/kit/namespaces'

module Saml
  module Kit
    module XmlParseable
      NAMESPACES = {
        NameFormat: ::Saml::Kit::Namespaces::ATTR_SPLAT,
        ds: ::Xml::Kit::Namespaces::XMLDSIG,
        md: ::Saml::Kit::Namespaces::METADATA,
        saml: ::Saml::Kit::Namespaces::ASSERTION,
        samlp: ::Saml::Kit::Namespaces::PROTOCOL,
        xmlenc: ::Xml::Kit::Namespaces::XMLENC,
      }.freeze

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
    end
  end
end
