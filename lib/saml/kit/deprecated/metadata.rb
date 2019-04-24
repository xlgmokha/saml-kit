# frozen_string_literal: true

module Saml
  module Kit
    class Metadata
      # @deprecated
      def organization_name
        Saml::Kit.deprecate('`organization_name` is deprecated. Use `organization.name`')
        organization.name
      end

      # @deprecated
      def organization_url
        Saml::Kit.deprecate('`organization_url` is deprecated. Use `organization.url`')
        organization.url
      end
    end
  end
end
