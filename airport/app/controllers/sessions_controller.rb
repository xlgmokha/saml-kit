class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  skip_before_action :authenticate!

  def new
    @saml_request = authentication_request
    @relay_state = JSON.generate(redirect_to: '/')
    @uri = URI.parse(idp_metadata.single_sign_on_service_for(binding: :http_redirect)[:location])
    @redirect_uri = redirect_url_for(@uri, @saml_request, @relay_state)
  end

  def create
    @saml_response = Saml::Kit::Response.parse(params[:SAMLResponse])
    return render :error, status: :forbidden if @saml_response.invalid?

    session[:user] = { id: @saml_response.name_id }.merge(@saml_response.attributes)
    redirect_to dashboard_path
  end

  private

  def redirect_url_for(uri, saml_request, relay_state)
    uri.to_s + '?' +
      {
      'SAMLRequest' => saml_request,
      'RelayState' => relay_state,
    }.map do |(x, y)|
      "#{x}=#{CGI.escape(y)}"
    end.join('&')
  end

  def idp_metadata
    Saml::Kit.configuration.registry.metadata_for(DEFAULT_IDP_ENTITY_ID)
  end

  def authentication_request
    builder = Saml::Kit::AuthenticationRequest::Builder.new
    builder.acs_url = session_url
    Saml::Kit::Request.serialize(builder)
  end
end
