Rails.application.routes.draw do
  get "dashboard", to: "dashboard#show", as: :dashboard
  resource :session, only: [:new, :create]
  resources :computers, only: [:index]
  root to: "sessions#new"
end
