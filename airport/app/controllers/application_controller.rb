class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  helper_method :current_user, :current_user?

  def current_user(issuer = params[:entity_id])
    return nil unless session[issuer].present?
    User.new(session[issuer].with_indifferent_access)
  end

  def current_user?(issuer)
    current_user(issuer).present?
  end
end
