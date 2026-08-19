# frozen_string_literal: true

module Saml
  module Kit
    # This class is responsible for validating and
    # parsing a SAML Response document.
    # {include:file:spec/examples/response_spec.rb}
    class Response < Document
      include Respondable
      extend Forwardable

      def_delegators :assertion, :name_id, :[], :attributes

      validate :must_be_valid_assertion
      validate :must_contain_single_assertion

      def initialize(
        xml,
        request_id: nil,
        configuration: Saml::Kit.configuration
      )
        @request_id = request_id
        super(xml, name: 'Response', configuration: configuration)
      end

      # The assertion consumer service url this response was received at.
      attr_reader :expected_recipient

      # Assigns the assertion consumer service url this response was received
      # at, forwarding it to the Assertion, which is what carries the
      # Recipient the specs ask us to compare against.
      def expected_recipient=(value)
        @expected_recipient = value
        return unless @assertion.is_a?(Saml::Kit::Assertion)

        @assertion.expected_recipient = value
      end

      def assertion(private_keys = configuration.private_keys(use: :encryption))
        @assertion ||= build_assertion(private_keys)
      end

      private

      def build_assertion(private_keys)
        node = assertion_nodes.last
        return Saml::Kit::NullAssertion.new if node.nil?

        assertion = Saml::Kit::Assertion.new(
          node, configuration: @configuration, private_keys: private_keys
        )
        assertion.expected_recipient = expected_recipient
        assertion
      end

      def signature_required_by_type?
        true
      end

      # `signed?` and `trusted?` deliberately report only this element's own
      # signature, but signing only the Assertion is a common identity provider
      # configuration, and that signature covers the identity being asserted.
      def signature_covers_document?
        signed? || assertion.signed?
      end

      def signature_trusted?
        super || (assertion.signed? && assertion.trusted?)
      end

      def must_be_valid_assertion
        assertion.valid?
        assertion.each_error do |attribute, error|
          attribute = :assertion if attribute == :base
          errors.add(attribute, error) unless errors.added?(attribute, error)
        end
      end

      def must_contain_single_assertion
        return if assertion_nodes.count <= 1

        errors.add(:base, error_message(:must_contain_single_assertion))
      end

      def assertion_nodes
        search(Saml::Kit::Assertion::XPATH)
      end
    end
  end
end
