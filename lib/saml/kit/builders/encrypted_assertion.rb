# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # This class is responsible for encrypting an Assertion.
      # {include:file:lib/saml/kit/builders/templates/encrypted_assertion.builder}
      class EncryptedAssertion
        include XmlTemplatable
        extend Forwardable

        attr_reader :assertion
        def_delegators :@response_builder,
          :configuration,
          :encryption_certificate

        def initialize(response_builder, assertion)
          @response_builder = response_builder
          @assertion = assertion
          @encrypt = true
        end
      end
    end
  end
end
