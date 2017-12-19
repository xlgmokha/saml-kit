module Saml
  module Kit
    module Buildable
      extend ActiveSupport::Concern

      class_methods do
        def build(*args, &block) # :yields builder
          builder(*args, &block).build
        end

        def build_xml(*args, &block) # :yields builder
          builder(*args, &block).to_xml
        end

        def builder(*args) # :yields builder
          builder_class.new(*args).tap do |builder|
            yield builder if block_given?
          end
        end
      end
    end
  end
end
