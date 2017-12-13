module Saml
  module Kit
    class Response < Document
      include Respondable

      validate :must_be_active_session
      validate :must_match_issuer

      def initialize(xml, request_id: nil)
        @request_id = request_id
        super(xml, name: "Response")
      end

      def name_id
        assertion.name_id
      end

      def [](key)
        attributes[key]
      end

      def attributes
        assertion.attributes
      end

      def started_at
        assertion.started_at
      end

      def expired_at
        assertion.expired_at
      end

      def expired?
        Time.current > expired_at
      end

      def active?
        Time.current > started_at && !expired?
      end

      def assertion
        @assertion = Saml::Kit::Assertion.new(content)
      end

      def signed?
        super || assertion.signed?
      end

      def certificate
        super || assertion.certificate
      end

      private

      def must_be_active_session
        return unless expected_type?
        return unless success?
        errors[:base] << error_message(:expired) unless active?
      end

      def must_match_issuer
        return unless expected_type?
        return unless success?

        unless audiences.include?(Saml::Kit.configuration.issuer)
          errors[:audience] << error_message(:must_match_issuer)
        end
      end

      def audiences
        assertion.audiences
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::Response::Builder', 'Saml::Kit::Builders::Response')
    end
  end
end
