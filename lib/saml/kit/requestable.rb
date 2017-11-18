module Saml
  module Kit
    module Requestable
      extend ActiveSupport::Concern

      included do
      end

      def query_string_parameter
        'SAMLRequest'
      end
    end
  end
end
