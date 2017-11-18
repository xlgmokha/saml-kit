module Saml
  module Kit
    module Respondable
      extend ActiveSupport::Concern

      included do
        validates_inclusion_of :status_code, in: [Namespaces::SUCCESS]
      end

      def query_string_parameter
        'SAMLResponse'
      end

      def status_code
        to_h.fetch(name, {}).fetch('Status', {}).fetch('StatusCode', {}).fetch('Value', nil)
      end

      def in_response_to
        to_h.fetch(name, {}).fetch('InResponseTo', nil)
      end
    end
  end
end
