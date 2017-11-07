class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  skip_before_action :authenticate!

  def new
    @uri = URI.parse(idp_metadata.single_sign_on_service_for(binding: :http_redirect)[:location])
    @redirect_uri = redirect_url_for(@uri)
  end

  def create
    saml_response = Saml::Kit::Response.parse(params[:SAMLResponse])
    session[:user] = { id: saml_response.name_id }.merge(saml_response.attributes)
    redirect_to dashboard_path
  end

  private

  def redirect_url_for(uri)
    uri.to_s + '?' +
      {
      'SAMLRequest' => Saml::Kit::Request.authentication(assertion_consumer_service: session_url),
      'RelayState' => JSON.generate(inbound_path: '/'),
    }.map do |(x, y)|
      "#{x}=#{CGI.escape(y)}"
    end.join('&')
  end

  def idp_metadata
    Saml::Kit.configuration.registry.metadata_for(DEFAULT_IDP_ENTITY_ID)
  end
end
