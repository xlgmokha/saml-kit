module Saml
  module Kit
    module Requestable
      extend ActiveSupport::Concern

      # @!visibility private
      def query_string_parameter
        'SAMLRequest'
      end
    end
  end
end
