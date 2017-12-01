module Saml
  module Kit
    module Buildable
      extend ActiveSupport::Concern

      class_methods do
        def build(*args)
          builder(*args).tap do |x|
            yield x if block_given?
          end.build
        end

        def builder(*args)
          builder_class.new(*args).tap do |builder|
            yield builder if block_given?
          end
        end
      end
    end
  end
end
