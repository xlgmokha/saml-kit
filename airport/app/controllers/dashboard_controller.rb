class DashboardController < ApplicationController
  def show
    @user_id = session[:user_id]
    @email = session[:email]
    @access_token = session[:access_token]
  end
end
