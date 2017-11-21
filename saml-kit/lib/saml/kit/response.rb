module Saml
  module Kit
    class Response < Document
      include Respondable

      validate :must_be_active_session
      validate :must_match_issuer

      def initialize(xml, request_id: nil)
        @request_id = request_id
        super(xml, name: "Response")
      end

      def name_id
        to_h.fetch(name, {}).fetch('Assertion', {}).fetch('Subject', {}).fetch('NameID', nil)
      end

      def [](key)
        attributes[key]
      end

      def attributes
        @attributes ||= Hash[to_h.fetch(name, {}).fetch('Assertion', {}).fetch('AttributeStatement', {}).fetch('Attribute', []).map do |item|
          [item['Name'].to_sym, item['AttributeValue']]
        end].with_indifferent_access
      end


      def started_at
        parse_date(to_h.fetch(name, {}).fetch('Assertion', {}).fetch('Conditions', {}).fetch('NotBefore', nil))
      end

      def expired_at
        parse_date(to_h.fetch(name, {}).fetch('Assertion', {}).fetch('Conditions', {}).fetch('NotOnOrAfter', nil))
      end

      def expired?
        Time.current > expired_at
      end

      def active?
        Time.current > started_at && !expired?
      end

      private

      def must_be_active_session
        return unless expected_type?
        return unless success?
        errors[:base] << error_message(:expired) unless active?
      end

      def must_match_issuer
        return unless expected_type?
        return unless success?

        unless audiences.include?(Saml::Kit.configuration.issuer)
          errors[:audience] << error_message(:must_match_issuer)
        end
      end

      def audiences
        Array(to_h[name]['Assertion']['Conditions']['AudienceRestriction']['Audience'])
      rescue => error
        Saml::Kit.logger.error(error)
        []
      end

      def parse_date(value)
        DateTime.parse(value)
      rescue => error
        Saml::Kit.logger.error(error)
        Time.at(0).to_datetime
      end

      class Builder
        attr_reader :user, :request
        attr_accessor :id, :reference_id, :now
        attr_accessor :version, :status_code
        attr_accessor :issuer, :sign, :destination

        def initialize(user, request)
          @user = user
          @request = request
          @id = SecureRandom.uuid
          @reference_id = SecureRandom.uuid
          @now = Time.now.utc
          @version = "2.0"
          @status_code = Namespaces::SUCCESS
          @issuer = configuration.issuer
          @destination = request.acs_url
          @sign = want_assertions_signed
        end

        def want_assertions_signed
          request.provider.want_assertions_signed
        rescue => error
          Saml::Kit.logger.error(error)
          true
        end

        def to_xml
          Signature.sign(id, sign: sign) do |xml, signature|
            xml.Response response_options do
              xml.Issuer(issuer, xmlns: Namespaces::ASSERTION)
              signature.template(xml)
              xml.Status do
                xml.StatusCode Value: status_code
              end
              xml.Assertion(assertion_options) do
                xml.Issuer issuer
                xml.Subject do
                  xml.NameID user.name_id_for(request.name_id_format), Format: request.name_id_format
                  xml.SubjectConfirmation Method: Namespaces::BEARER do
                    xml.SubjectConfirmationData "", subject_confirmation_data_options
                  end
                end
                xml.Conditions conditions_options do
                  xml.AudienceRestriction do
                    xml.Audience request.issuer
                  end
                end
                xml.AuthnStatement authn_statement_options do
                  xml.AuthnContext do
                    xml.AuthnContextClassRef Namespaces::PASSWORD
                  end
                end
                assertion_attributes = user.assertion_attributes_for(request)
                if assertion_attributes.any?
                  xml.AttributeStatement do
                    assertion_attributes.each do |key, value|
                      xml.Attribute Name: key, NameFormat: Namespaces::URI, FriendlyName: key do
                        xml.AttributeValue value.to_s
                      end
                    end
                  end
                end
              end
            end
          end
        end

        def build
          Response.new(to_xml, request_id: request.id)
        end

        private

        def configuration
          Saml::Kit.configuration
        end

        def response_options
          {
            ID: id.present? ? "_#{id}" : nil,
            Version: version,
            IssueInstant: now.iso8601,
            Destination: destination,
            Consent: Namespaces::UNSPECIFIED,
            InResponseTo: request.id,
            xmlns: Namespaces::PROTOCOL,
          }
        end

        def assertion_options
          {
            ID: "_#{reference_id}",
            IssueInstant: now.iso8601,
            Version: "2.0",
            xmlns: Namespaces::ASSERTION,
          }
        end

        def subject_confirmation_data_options
          {
            InResponseTo: request.id,
            NotOnOrAfter: 3.hours.since(now).utc.iso8601,
            Recipient: request.acs_url,
          }
        end

        def conditions_options
          {
            NotBefore: now.utc.iso8601,
            NotOnOrAfter: Saml::Kit.configuration.session_timeout.from_now.utc.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: now.iso8601,
            SessionIndex: assertion_options[:ID],
            SessionNotOnOrAfter: 3.hours.since(now).utc.iso8601,
          }
        end
      end
    end
  end
end
