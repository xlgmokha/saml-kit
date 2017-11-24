class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  def render_error(status, model: nil)
    @model = model
    render template: "errors/#{status}", status: status
  end

  def current_user
    return nil if session[:user_id].blank?
    @current_user ||= User.find(session[:user_id])
  rescue ActiveRecord::RecordNotFound => error
    logger.error(error)
    nil
  end

  def current_user?
    current_user.present?
  end
end
