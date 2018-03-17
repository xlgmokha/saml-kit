
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
          attribute = item.at_xpath('./saml:AttributeValue', namespace)
          memo[item.attribute('Name').value] = attribute.try(:text)
          memo
        end.with_indifferent_access
      end
    end
  end
end
