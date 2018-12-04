# frozen_string_literal: true

module Saml
  module Kit
    class AttributeStatement
      include XmlParseable

      attr_reader :content

      def initialize(node)
        @to_nokogiri = node
        @content = node.to_s
      end

      def attributes
        @attributes ||= search('./saml:Attribute').inject({}) do |memo, item|
          namespace = Saml::Kit::Document::NAMESPACES
          values = item.search('./saml:AttributeValue', namespace)
          memo[item.attribute('Name').value] = values.length == 1 ? values[0].try(:text) : values.map { |x| x.try(:text) }
          memo
        end.with_indifferent_access
      end
    end
  end
end
