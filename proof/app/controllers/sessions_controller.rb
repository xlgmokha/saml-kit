class SessionsController < ApplicationController
  before_action :validate_saml_request, only: [:new, :create]

  def new
  end

  def create
    if user = User.login(user_params[:email], user_params[:password])
      create_session_for(user)
      post_to_service_provider(user)
    else
      redirect_to new_session_path(saml_params), error: "Invalid Credentials"
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
  end

  def create_session_for(user)
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
    @saml_request = Saml::Kit::Request.decode(raw_saml_request)
    head(:forbidden) unless @saml_request.valid?
  end
end
