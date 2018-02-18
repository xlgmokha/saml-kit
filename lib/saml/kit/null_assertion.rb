module Saml
  module Kit
    class NullAssertion
      include ActiveModel::Validations
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
        Time.at(0).to_datetime
      end

      def expired_at
        Time.at(0).to_datetime
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
        errors[:assertion].push(error_message(:invalid))
      end

      def name
        'NullAssertion'
      end
    end
  end
end
