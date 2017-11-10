class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  def render_error(status, item: nil)
    @item = item
    render template: "errors/#{status}", status: status
  end
end
