class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:new]
  before_action :load_saml_request, only: [:new, :create]

  def new
    session[:SAMLRequest] ||= params[:SAMLRequest]
    session[:RelayState] ||= params[:RelayState]
  end

  def create
    if user = User.login(user_params[:email], user_params[:password])
      reset_session
      session[:user_id] = user.id
      @saml_response = @saml_request.response_for(user)
      @relay_state = params[:RelayState]
      render layout: nil
    else
      redirect_to new_session_path, error: "Invalid Credentials"
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
  end

  def load_saml_request(raw_saml_request = session[:SAMLRequest] || params[:SAMLRequest])
    @saml_request = Saml::Kit::Request.deserialize(raw_saml_request)
    if @saml_request.invalid?
      render_error(:forbidden, model: @saml_request)
    end
  end
end
