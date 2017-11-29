module Saml
  module Kit
    class LogoutResponse < Document
      include Respondable

      def initialize(xml, request_id: nil)
        @request_id = request_id
        super(xml, name: "LogoutResponse")
      end
    end
  end
end
