class SessionsController < ApplicationController
  before_action :validate_saml_request, only: [:new, :create]

  def new
  end

  def create
    if user_params[:email].blank? || user_params[:password].blank?
      return render_invalid_credentials
    end

    user = User.find_by!(email: user_params[:email])
    if user.authenticate(user_params[:password])
      create_user_session(user)
      post_to_service_provider(user)
    else
      render_invalid_credentials
    end
  rescue ActiveRecord::RecordNotFound
    render_invalid_credentials
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
    @saml_response = @saml_request.response_for(user)
    @relay_state = params[:RelayState]
    render template: "sessions/saml_post", layout: nil
  end

  def saml_params(storage = params)
    {
      RelayState: storage[:RelayState],
      SAMLRequest: storage[:SAMLRequest],
    }
  end

  def validate_saml_request(raw_saml_request = params[:SAMLRequest])
    @saml_request = Saml::Kit::SamlRequest.decode(raw_saml_request)
    render_http_status(:forbidden) unless @saml_request.valid?
  end

  def render_http_status(status = :forbidden)
    head :status
  end

  def render_invalid_credentials
    redirect_to new_session_path(saml_params), error: "Invalid Credentials"
  end
end
