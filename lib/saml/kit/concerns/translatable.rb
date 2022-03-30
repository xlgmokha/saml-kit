# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible
    # for translating error messages
    # to the current locale.
    module Translatable
      # @!visibility private
      def error_message(attribute, options = {})
        default_options = { scope: "saml/kit.errors.#{name}" }
        I18n.translate(attribute, **default_options.merge(options))
      end
    end
  end
end
