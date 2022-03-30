# frozen_string_literal: true

module Saml
  module Kit
    # This class is an implementation of the
    # Null Object pattern for when a Response
    # is missing an Assertion.
    class NullAssertion
      include Validatable
      include Translatable
      validate :invalid

      def issuer; end

      def name_id; end

      def signed?
        false
      end

      def signature; end

      def attributes
        []
      end

      def started_at
        Time.at(0)
      end

      def expired_at
        Time.at(0)
      end

      def audiences
        []
      end

      def encrypted?
        false
      end

      def decryptable?
        false
      end

      def present?
        false
      end

      def to_xml(*_args)
        ''
      end

      def invalid
        errors.add(:assertion, error_message(:invalid))
      end

      def name
        'NullAssertion'
      end
    end
  end
end
