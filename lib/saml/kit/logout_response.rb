module Saml
  module Kit
    # This class is used to parse a LogoutResponse SAML document.
    #
    #   document = Saml::Kit::LogoutResponse.new(raw_xml)
    #
    # {include:file:spec/examples/logout_response_spec.rb}
    class LogoutResponse < Document
      include Respondable

      def initialize(xml, request_id: nil, configuration: Saml::Kit.configuration)
        @request_id = request_id
        super(xml, name: "LogoutResponse", configuration: configuration)
      end
    end
  end
end
