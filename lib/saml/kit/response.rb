module Saml
  module Kit
    # {include:file:spec/examples/response_spec.rb}
    class Response < Document
      include Respondable
      extend Forwardable

      def_delegators :assertion, :name_id, :[], :attributes

      validate :must_be_valid_assertion
      validate :must_contain_single_assertion

      def initialize(xml, request_id: nil, configuration: Saml::Kit.configuration)
        @request_id = request_id
        super(xml, name: "Response", configuration: configuration)
      end

      def assertion(private_keys = configuration.private_keys(use: :encryption))
        @assertion ||=
          begin
            node = assertion_nodes.last
            if node.nil?
              Saml::Kit::NullAssertion.new
            else
              Saml::Kit::Assertion.new(node, configuration: @configuration, private_keys: private_keys)
            end
          end
      end

      private

      def must_be_valid_assertion
        assertion.valid?
        assertion.errors.each do |attribute, error|
          self.errors[attribute] << error
        end
      end

      def must_contain_single_assertion
        if assertion_nodes.count > 1
          errors[:base] << error_message(:must_contain_single_assertion)
        end
      end

      def assertion_nodes
        search(Saml::Kit::Assertion::XPATH)
      end
    end
  end
end
