module Saml
  module Kit
    class Response < Document
      include Respondable
      extend Forwardable

      def_delegators :assertion, :name_id, :[], :attributes

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
          self.errors[attribute] << error
        end
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::Response::Builder', 'Saml::Kit::Builders::Response')
    end
  end
end
