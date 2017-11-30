module Saml
  module Kit
    module Buildable
      extend ActiveSupport::Concern

      class_methods do
        def build(*args)
          builder = builder_class.new(*args)
          yield builder if block_given?
          builder.build
        end
      end
    end
  end
end
