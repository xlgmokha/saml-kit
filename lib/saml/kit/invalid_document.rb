module Saml
  module Kit
    # {include:file:spec/saml/invalid_document_spec.rb}
    class InvalidDocument < Document
      validate do |model|
        model.errors[:base] << model.error_message(:invalid)
      end

      def initialize(xml, configuration: nil)
        super(xml, name: "InvalidDocument")
      end

      def to_h
        super
      rescue
        {}
      end
    end
  end
end
