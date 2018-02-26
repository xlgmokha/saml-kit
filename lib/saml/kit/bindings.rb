# frozen_string_literal: true

require 'saml/kit/bindings/binding'
require 'saml/kit/bindings/http_post'
require 'saml/kit/bindings/http_redirect'
require 'saml/kit/bindings/url_builder'

module Saml
  module Kit
    module Bindings
      HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'.freeze
      HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'.freeze
      HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'.freeze
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
