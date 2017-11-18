class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:new, :destroy]
  before_action :load_saml_request, only: [:new, :create, :destroy]

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
      render layout: "spinner"
    else
      redirect_to new_session_path, error: "Invalid Credentials"
    end
  end

  def destroy
    user = User.find_by(uuid: @saml_request.name_id)
    @saml_response = @saml_request.response_for(user)
    @relay_state = params[:RelayState]
    reset_session
    render layout: "spinner"
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
  end

  def load_saml_request(raw_saml_request = session[:SAMLRequest] || params[:SAMLRequest])
    saml_binding = binding_for(request)
    @saml_request = saml_binding.deserialize(params)
    if @saml_request.invalid?
      render_error(:forbidden, model: @saml_request)
    end
  end

  def idp
    Idp.default(request)
  end

  def binding_for(request)
    if request.post?
      idp.single_sign_on_service_for(binding: :post)
    else
      idp.single_sign_on_service_for(binding: :http_redirect)
    end
  end
end
