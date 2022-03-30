# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for
    # providing an API to build a
    # document object, xml, or builder class.
    module Buildable
      extend ActiveSupport::Concern

      class_methods do
        def build(*args, **kwargs)
          builder(*args, **kwargs) do |builder|
            yield builder if block_given?
          end.build
        end

        def build_xml(*args, **kwargs)
          builder(*args, **kwargs) do |builder|
            yield builder if block_given?
          end.to_xml
        end

        def builder(*args, **kwargs)
          builder_class.new(*args, **kwargs).tap do |builder|
            yield builder if block_given?
          end
        end
      end
    end
  end
end
