module Saml
  module Kit
    module Buildable
      extend ActiveSupport::Concern

      class_methods do
        def build
          builder = builder_class.new
          yield builder if block_given?
          builder.build
        end
      end
    end
  end
end
