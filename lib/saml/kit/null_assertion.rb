module Saml
  module Kit
    class NullAssertion
      include ActiveModel::Validations
      include Translatable
      validate :invalid

      def invalid
        errors[:assertion].push(error_message(:invalid))
      end

      def name
        "NullAssertion"
      end
    end
  end
end
