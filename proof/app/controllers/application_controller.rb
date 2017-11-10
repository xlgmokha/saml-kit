class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  def render_error(status, model: nil)
    @model = model
    render template: "errors/#{status}", status: status
  end
end
