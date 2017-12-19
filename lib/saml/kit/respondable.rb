module Saml
  module Kit
    module Respondable
      extend ActiveSupport::Concern
      attr_reader :request_id

      included do
        validates_inclusion_of :status_code, in: [Namespaces::SUCCESS]
        validate :must_match_request_id
      end

      # @!visibility private
      def query_string_parameter
        'SAMLResponse'
      end

      # Returns the /Status/StatusCode@Value
      def status_code
        to_h.fetch(name, {}).fetch('Status', {}).fetch('StatusCode', {}).fetch('Value', nil)
      end

      # Returns the /InResponseTo attribute.
      def in_response_to
        to_h.fetch(name, {}).fetch('InResponseTo', nil)
      end

      # Returns true if the Status code is #{Saml::Kit::Namespaces::SUCCESS}
      def success?
        Namespaces::SUCCESS == status_code
      end

      private

      def must_match_request_id
        return if request_id.nil?

        if in_response_to != request_id
          errors[:in_response_to] << error_message(:invalid_response_to)
        end
      end
    end
  end
end
