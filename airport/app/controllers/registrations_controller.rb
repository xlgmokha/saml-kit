class RegistrationsController < ApplicationController
  def index
    @metadatum = Metadatum.all.limit(10)
  end

  def show
    metadatum = Metadatum.find(params[:id])
    render xml: metadatum.to_xml
  end

  def new
  end

  def create
    Saml::Kit.configuration.registry.register_url(params[:url], verify_ssl: Rails.env.production?)
  end
end
