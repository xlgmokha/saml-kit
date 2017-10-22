class ComputersController < ApplicationController
  def index
    @computers = ApiClient.new(session).computers
  rescue => error
    @error = error
  end
end
