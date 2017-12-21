module Saml
  module Kit
    # This class is used to parse a LogoutResponse SAML document.
    #
    #   document = Saml::Kit::LogoutResponse.new(raw_xml)
    class LogoutResponse < Document
      include Respondable

      def initialize(xml, request_id: nil, configuration: Saml::Kit.configuration)
        @request_id = request_id
        super(xml, name: "LogoutResponse", configuration: configuration)
      end

      # @deprecated Use {#Saml::Kit::Builders::LogoutResponse} instead of this.
      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::LogoutResponse::Builder', 'Saml::Kit::Builders::LogoutResponse')
    end
  end
end
