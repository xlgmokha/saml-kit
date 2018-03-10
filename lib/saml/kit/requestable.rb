# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for providing
    # the functionality available to all
    # SAML request documents.
    # e.g. AuthnRequest, LogoutRequest.
    module Requestable
      extend ActiveSupport::Concern

      # @!visibility private
      def query_string_parameter
        'SAMLRequest'
      end
    end
  end
end
