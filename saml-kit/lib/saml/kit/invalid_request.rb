module Saml
  module Kit
    class InvalidRequest
      include ActiveModel::Validations
      include XsdValidatable
      attr_reader :raw, :name

      validate do |model|
        model.errors[:base] << model.error_message(:invalid)
      end

      def initialize(raw)
        @raw = raw
        @name = "InvalidRequest"
      end

      def to_xml
        raw
      end
    end
  end
end
