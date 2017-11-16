module Saml
  module Kit
    class InvalidDocument
      include ActiveModel::Validations
      include XsdValidatable
      attr_reader :raw, :name

      validate do |model|
        model.errors[:base] << model.error_message(:invalid)
      end

      def initialize(raw, name)
        @raw = raw
      end

      def to_xml
        raw
      end

    end

    class InvalidRequest < InvalidDocument
      def initialize(raw)
        super raw, "InvalidRequest"
      end
    end

    class InvalidResponse < InvalidDocument
      def initialize(raw)
        super raw, "InvalidResponse"
      end
    end
  end
end
