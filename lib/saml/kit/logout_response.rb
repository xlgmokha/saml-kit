# frozen_string_literal: true

module Saml
  module Kit
    # This class is used to parse a LogoutResponse SAML document.
    #
    #   document = Saml::Kit::LogoutResponse.new(raw_xml)
    #
    # {include:file:spec/examples/logout_response_spec.rb}
    class LogoutResponse < Document
      include Respondable

      def initialize(
        xml, request_id: nil, configuration: Saml::Kit.configuration
      )
        @request_id = request_id
        super(xml, name: 'LogoutResponse', configuration: configuration)
      end

      private

      # Profiles 4.4.3.4 requires a LogoutResponse to be signed when it is
      # delivered by the POST or Redirect binding. See LogoutRequest for why
      # this is opt in until 2.0.0.
      def signature_required_by_type?
        configuration.logout_signature_required
      end
    end
  end
end
