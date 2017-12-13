module Saml
  module Kit
    class Response < Document
      include Respondable
      extend Forwardable

      def_delegators :assertion, :name_id, :[], :attributes, :started_at, :expired_at, :audiences

      validate :must_be_active_session
      validate :must_match_issuer

      def initialize(xml, request_id: nil)
        @request_id = request_id
        super(xml, name: "Response")
      end

      def expired?
        Time.current > expired_at
      end

      def active?
        Time.current > started_at && !expired?
      end

      def assertion
        @assertion = Saml::Kit::Assertion.new(to_h)
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

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::Response::Builder', 'Saml::Kit::Builders::Response')
    end
  end
end
