class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  skip_before_action :authenticate!

  def new
    @saml_request = idp_metadata.build_request(Saml::Kit::AuthenticationRequest).serialize
    @relay_state = JSON.generate(redirect_to: '/')
    @post_uri = idp_metadata.single_sign_on_service_for(binding: :post)
    @redirect_uri = http_redirect_url_for_login(@saml_request, @relay_state)
  end

  def create
    @saml_response = Saml::Kit::Response.deserialize(params[:SAMLResponse])
    return render :error, status: :forbidden if @saml_response.invalid?

    session[:user] = { id: @saml_response.name_id }.merge(@saml_response.attributes)
    redirect_to dashboard_path
  end

  def destroy
    @post_uri = idp_metadata.single_logout_service_for(:post)
    @saml_request = idp_metadata.build_request(Saml::Kit::LogoutRequest).serialize
  end

  private

  def idp_metadata
    Rails.configuration.x.idp_metadata
  end

  def http_redirect_url_for_login(saml_request, relay_state)
    UrlBuilder.new.http_redirect_url_for(
      idp_metadata.single_sign_on_service_for(binding: :http_redirect),
      saml_request,
      relay_state
    )
  end
end
