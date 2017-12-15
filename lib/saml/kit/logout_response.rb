module Saml
  module Kit
    class LogoutResponse < Document
      include Respondable

      def initialize(xml, request_id: nil, configuration: Saml::Kit.configuration)
        @request_id = request_id
        super(xml, name: "LogoutResponse", configuration: configuration)
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::LogoutResponse::Builder', 'Saml::Kit::Builders::LogoutResponse')
    end
  end
end
