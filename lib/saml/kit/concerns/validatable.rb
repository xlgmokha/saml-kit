# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for
    # providing an adapter to the ActiveModel::Validations
    # module.
    module Validatable
      extend ActiveSupport::Concern
      include ActiveModel::Validations

      def each_error
        if Gem::Requirement.new('>= 6.1').satisfied_by?(ActiveModel.version)
          errors.each do |error|
            yield error.attribute, error.message
          end
        else
          errors.each do |attribute, message|
            yield attribute, message
          end
        end
      end
    end
  end
end
