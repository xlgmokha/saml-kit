class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  skip_before_action :authenticate!

  def new
    @saml_request = authentication_request
    @relay_state = JSON.generate(redirect_to: '/')
    @post_uri = idp_metadata.single_sign_on_service_for(binding: :post)
    @redirect_uri = redirect_url_for(@saml_request, @relay_state)
  end

  def create
    @saml_response = Saml::Kit::Response.deserialize(params[:SAMLResponse])
    return render :error, status: :forbidden if @saml_response.invalid?

    session[:user] = { id: @saml_response.name_id }.merge(@saml_response.attributes)
    redirect_to dashboard_path
  end

  def destroy
    @uri = idp_metadata.single_logout_service_for(:post)
    @logout_request = idp_metadata.build_logout_request.serialize
  end

  private

  def redirect_url_for(saml_request, relay_state)
    uri = idp_metadata.single_sign_on_service_for(binding: :http_redirect)
    uri.to_s + '?' + {
      'SAMLRequest' => saml_request,
      'RelayState' => relay_state,
    }.map do |(x, y)|
      "#{x}=#{CGI.escape(y)}"
    end.join('&')
  end

  def idp_metadata
    Rails.configuration.x.idp_metadata
  end

  def authentication_request
    idp_metadata.build_authentication_request.serialize
  end
end
