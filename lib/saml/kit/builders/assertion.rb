# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # This class is responsible for building a SAML Assertion
      # {include:file:lib/saml/kit/builders/templates/assertion.builder}
      class Assertion
        include XmlTemplatable

        attr_reader :user, :request, :configuration
        attr_accessor :reference_id
        attr_accessor :now, :destination
        attr_accessor :issuer, :version
        attr_accessor :default_name_id_format
        attr_writer :audience

        def initialize(user, request, configuration: Saml::Kit.configuration)
          @user = user
          @request = request
          @configuration = configuration
          @issuer = configuration.entity_id
          @reference_id = ::Xml::Kit::Id.generate
          @version = '2.0'
          @now = Time.now.utc
          self.default_name_id_format = Saml::Kit::Namespaces::UNSPECIFIED_NAMEID
        end

        # The audience this assertion is addressed to.
        #
        # Defaults to the requesting service provider, so a solicited
        # assertion is unchanged. An unsolicited one has no request to derive
        # it from, so only the caller can supply it.
        def audience
          @audience || request.try(:issuer)
        end

        def name_id_format
          request.try(:name_id_format)
        end

        def name_id
          user.name_id_for(name_id_format)
        end

        def assertion_attributes
          return {} unless user.respond_to?(:assertion_attributes_for)

          user.assertion_attributes_for(request)
        end

        def build
          Saml::Kit::Assertion.new(to_xml, configuration: configuration)
        end

        private

        # Profiles 4.1.4.2 requires an AudienceRestriction on every assertion
        # carrying a bearer subject confirmation, and says so unconditionally
        # -- it covers the case where the response answers no request.
        #
        # An assertion with no audience is accepted by every service provider
        # trusting the issuer, so emitting one is a defect we warn about now
        # and refuse in 2.0.0.
        def audience_restriction_for(xml)
          return warn_missing_audience if audience.blank?

          xml.AudienceRestriction { xml.Audience audience }
        end

        def warn_missing_audience
          Saml::Kit.warn_conformance(
            'Building an Assertion with no AudienceRestriction'
          )
        end

        def assertion_options
          {
            ID: reference_id,
            IssueInstant: now.iso8601,
            Version: version,
            xmlns: Namespaces::ASSERTION,
          }
        end

        def subject_confirmation_data_options
          options = {}
          options[:InResponseTo] = request.id if request.present?
          options[:Recipient] = destination if destination.present?
          options[:NotOnOrAfter] = (now + 5.minutes).utc.iso8601
          options
        end

        def conditions_options
          {
            NotBefore: now.utc.iso8601,
            NotOnOrAfter: not_on_or_after.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: now.iso8601,
            SessionIndex: reference_id,
          }
        end

        def name_id_options
          { Format: name_id_format || default_name_id_format }
        end

        def not_on_or_after
          configuration.session_timeout.since(now).utc
        end
      end
    end
  end
end
