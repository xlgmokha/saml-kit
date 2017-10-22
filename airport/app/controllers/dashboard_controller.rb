class DashboardController < ApplicationController
  def show
    @user_id = session[:user_id]
    @email = session[:email]
  end
end
