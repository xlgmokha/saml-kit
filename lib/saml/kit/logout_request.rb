module Saml
  module Kit
    class LogoutRequest < Document
      include Requestable
      validates_presence_of :single_logout_service, if: :expected_type?

      def initialize(xml)
        super(xml, name: "LogoutRequest")
      end

      def name_id
        to_h[name]['NameID']
      end

      def single_logout_service
        return if provider.nil?
        urls = provider.single_logout_services
        urls.first
      end

      def response_for(user)
        Saml::Kit::Builders::LogoutResponse.new(user, self)
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::LogoutRequest::Builder', 'Saml::Kit::Builders::LogoutRequest')
    end
  end
end
