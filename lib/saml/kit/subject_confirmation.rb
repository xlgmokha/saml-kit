# frozen_string_literal: true

module Saml
  module Kit
    # This class represents a SubjectConfirmation element
    # nested in the Subject of an Assertion.
    class SubjectConfirmation
      include XmlParseable

      attr_reader :content

      def initialize(node)
        @to_nokogiri = node
        @content = node.to_s
      end

      # Returns the Method attribute.
      #
      # Named to avoid shadowing `Object#method`.
      def confirmation_method
        at_xpath('./@Method').try(:value)
      end

      # Returns true when this confirms a bearer subject, which is the only
      # method the Web Browser SSO profile uses.
      def bearer?
        confirmation_method == Namespaces::BEARER
      end

      # Returns the SubjectConfirmationData/@Recipient attribute.
      def recipient
        data_attribute('Recipient')
      end

      # Returns the SubjectConfirmationData/@InResponseTo attribute.
      def in_response_to
        data_attribute('InResponseTo')
      end

      # Returns the SubjectConfirmationData/@NotOnOrAfter attribute, or nil
      # when it is absent.
      def expired_at
        parse_attribute('NotOnOrAfter')
      end

      # Returns the SubjectConfirmationData/@NotBefore attribute, or nil when
      # it is absent. Profiles 4.1.4.2 requires this to be absent.
      def started_at
        parse_attribute('NotBefore')
      end

      # Returns true when NotOnOrAfter is present and has passed.
      def expired?(now)
        expired_at.present? && now >= expired_at
      end

      private

      def parse_attribute(name)
        value = data_attribute(name)
        parse_iso8601(value) if value.present?
      end

      def data_attribute(name)
        at_xpath("./saml:SubjectConfirmationData/@#{name}").try(:value)
      end
    end
  end
end
