module Saml
  module Kit
    module Translatable
      # @!visibility private
      def error_message(attribute, type: :invalid)
        I18n.translate(attribute, scope: "saml/kit.errors.#{name}")
      end
    end
  end
end
