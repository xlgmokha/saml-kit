Rails.application.routes.draw do
  get "dashboard", to: "dashboard#show", as: :dashboard
  resource :session, only: [:new, :create, :destroy]
  resource :assertion, only: [:create, :destroy]
  post "/assertions/consume" => "assertions#create", as: :consume
  post "/assertions/logout" => "assertions#destroy", as: :logout
  resource :metadata, only: [:show]
  resources :computers, only: [:index]
  root to: "sessions#new"
end
