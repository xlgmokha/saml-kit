module Saml
  module Kit
    class Response < Document
      include Respondable
      extend Forwardable

      def_delegators :assertion, :name_id, :[], :attributes, :active?, :audiences

      validate :must_match_issuer
      validate :must_be_valid_assertion

      def initialize(xml, request_id: nil, configuration: Saml::Kit.configuration)
        @request_id = request_id
        super(xml, name: "Response", configuration: configuration)
      end

      def assertion
        @assertion ||= Saml::Kit::Assertion.new(to_h, configuration: @configuration)
      end

      private

      def must_be_valid_assertion
        assertion.valid?
        assertion.errors.each do |attribute, error|
          self.errors[:assertion] << error
        end
      end

      def must_match_issuer
        return unless expected_type?
        return unless success?

        unless audiences.include?(configuration.issuer)
          errors[:audience] << error_message(:must_match_issuer)
        end
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::Response::Builder', 'Saml::Kit::Builders::Response')
    end
  end
end
