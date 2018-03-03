# frozen_string_literal: true

module Saml
  module Kit
    # {include:file:spec/saml/kit/invalid_document_spec.rb}
    class InvalidDocument < Document
      validate do |model|
        model.errors[:base] << model.error_message(:invalid)
      end

      def initialize(xml, configuration: nil)
        super(xml, name: 'InvalidDocument')
      end

      def to_h
        super
      rescue StandardError
        {}
      end
    end
  end
end
