module Saml
  module Kit
    module Bindings
      class Binding
        attr_reader :binding, :location

        def initialize(binding:, location:)
          @binding = binding
          @location = location
        end

        def binding?(other)
          binding == other
        end

        def serialize(builder, relay_state: nil)
          []
        end

        def deserialize(params)
          raise ArgumentError.new("Unsupported binding")
        end

        def to_h
          { binding: binding, location: location }
        end

        def ==(other)
          self.to_s == other.to_s
        end

        def eql?(other)
          self == other
        end

        def hash
          to_s.hash
        end

        def to_s
          "#{location}#{binding}"
        end

        protected

        def saml_param_from(params)
          if params['SAMLRequest'].present?
            params['SAMLRequest']
          elsif params['SAMLResponse'].present?
            params['SAMLResponse']
          else
            raise ArgumentError.new("SAMLRequest or SAMLResponse parameter is required.")
          end
        end
      end
    end
  end
end
