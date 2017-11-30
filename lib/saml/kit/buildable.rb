module Saml
  module Kit
    module Buildable
      extend ActiveSupport::Concern

      class_methods do
        def build
          puts builder_class.inspect
          builder = builder_class.new
          yield builder
          builder.build
        end
      end
    end
  end
end
