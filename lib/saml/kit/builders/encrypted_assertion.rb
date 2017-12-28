module Saml
  module Kit
    module Builders
      class EncryptedAssertion
        include XmlTemplatable
        extend Forwardable

        attr_reader :assertion
        attr_reader :encrypt
        def_delegators :@response_builder, :configuration, :encryption_certificate

        def initialize(response_builder, assertion)
          @response_builder = response_builder
          @assertion = assertion
          @encrypt = true
        end
      end
    end
  end
end
