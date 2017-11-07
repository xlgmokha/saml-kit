Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  resource :session, only: [:new, :create, :destroy]
  post "/session/new" => "sessions#new"
  resource :metadata, only: [:show]
  root to: "sessions#new"
end
