Rails.application.routes.draw do
  get "dashboard", to: "dashboard#show", as: :dashboard
  resource :session, only: [:new, :create]
  resource :metadata, only: [:show]
  resources :computers, only: [:index]
  root to: "sessions#new"
end
