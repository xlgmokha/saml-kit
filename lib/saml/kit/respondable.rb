module Saml
  module Kit
    module Respondable
      extend ActiveSupport::Concern

      included do
        validate :must_be_response
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

      def must_be_response
        return if to_xml.blank?

        errors[:base] << error_message(:invalid) unless response?
      end

      def response?
        return false if to_xml.blank?
        to_h[name].present?
      end
    end
  end
end
