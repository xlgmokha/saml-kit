module Saml
  module Kit
    module Requestable
      extend ActiveSupport::Concern
      included do
        validate :must_be_request
      end

      def query_string_parameter
        'SAMLRequest'
      end

      def must_be_request
        return if to_h.nil?

        errors[:base] << error_message(:invalid) unless request?
      end

      def request?
        return false if to_xml.blank?
        to_h[name].present?
      end
    end
  end
end
