class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  helper_method :current_user
  before_action :authenticate!

  def current_user
    return nil unless session[:user].present?
    @current_user ||= User.new(session[:user].with_indifferent_access)
  end

  def current_user?
    current_user.present?
  end

  def authenticate!
    redirect_to new_session_path unless current_user?
  end
end
