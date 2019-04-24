# frozen_string_literal: true

require 'saml/kit/bindings/binding'
require 'saml/kit/bindings/http_post'
require 'saml/kit/bindings/http_redirect'
require 'saml/kit/bindings/url_builder'

module Saml
  module Kit
    # This module is responsible for exposing
    # the different SAML bindings that are
    # supported by this gem.
    module Bindings
      BINDINGS_2_0 = 'urn:oasis:names:tc:SAML:2.0:bindings'
      HTTP_ARTIFACT = "#{BINDINGS_2_0}:HTTP-Artifact"
      HTTP_POST = "#{BINDINGS_2_0}:HTTP-POST"
      HTTP_REDIRECT = "#{BINDINGS_2_0}:HTTP-Redirect"
      ALL = {
        http_post: HTTP_POST,
        http_redirect: HTTP_REDIRECT,
        http_artifact: HTTP_ARTIFACT,
      }.freeze

      def self.binding_for(binding)
        ALL[binding]
      end

      def self.to_symbol(binding)
        case binding
        when HTTP_REDIRECT
          :http_redirect
        when HTTP_POST
          :http_post
        else
          binding
        end
      end

      def self.create_for(binding, location)
        case binding
        when HTTP_REDIRECT
          HttpRedirect.new(location: location)
        when HTTP_POST
          HttpPost.new(location: location)
        else
          Binding.new(binding: binding, location: location)
        end
      end
    end
  end
end
