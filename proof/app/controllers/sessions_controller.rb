class SessionsController < ApplicationController
  before_action :validate_saml_request, only: [:new, :create]

  def new
  end

  def create
    if user_params[:email].blank? || user_params[:password].blank?
      return redirect_to new_session_path(saml_params), error: "Invalid Credentials"
    end

    user = User.find_by(email: user_params[:email])
    if user.try(:authenticate, user_params[:password])
      create_user_session(user)
      post_to_service_provider(user)
    else
      redirect_to new_session_path(saml_params), error: "Invalid Credentials"
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
  end

  def create_user_session(user)
    reset_session
    session[:user_id] = user.id
  end

  def post_to_service_provider(user)
    @saml_response = encode_response(user)
    render template: "amp_authentication/sessions/saml_post", layout: nil
  end

  def saml_params(storage = params)
    {
      RelayState: storage[:RelayState],
      SAMLRequest: storage[:SAMLRequest],
    }
  end

  def validate_saml_request(raw_saml_request = params[:SAMLRequest])
    #decode_request(raw_saml_request)
    saml_request = SamlRequest.decode(raw_saml_request)
    render_http_status(:forbidden) unless saml_request.valid?
  end

  def render_http_status(status = :forbidden)
    head :status
  end
end
