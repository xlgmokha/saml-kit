module Saml
  module Kit
    class InvalidDocument
      include ActiveModel::Validations
      include XsdValidatable
      attr_reader :raw, :name

      validate do |model|
        model.errors[:base] << model.error_message(:invalid)
      end

      def initialize(raw)
        @raw = raw
        @name = "InvalidDocument"
      end

      def to_xml
        raw
      end
    end
  end
end
