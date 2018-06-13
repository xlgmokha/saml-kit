module Saml
  module Kit
    class Organization
      include XmlParseable

      attr_reader :content

      def initialize(node)
        @to_nokogiri = node
        @content = node.to_s
      end

      # Returns the Organization Name
      def name
        at_xpath('./md:OrganizationName').try(:text)
      end

      # Returns the Organization URL
      def url
        at_xpath('./md:OrganizationURL').try(:text)
      end

      # @deprecated
      def organization_name
        Saml::Kit.deprecate('`organization_name` is deprecated. Use `organization.name`')
        name
      end

      # @deprecated
      def organization_url
        Saml::Kit.deprecate('`organization_url` is deprecated. Use `organization.url`')
        url
      end
    end
  end
end
