class MetadataRegistry
  def register_url(url, verify_ssl: true)
    content = Saml::Kit::DefaultRegistry::HttpApi.new(url, verify_ssl: verify_ssl).get
    register(Saml::Kit::Metadata.from(content))
  end

  def register(metadata)
    record = Metadatum.find_or_create_by!(issuer: metadata.entity_id)
    record.metadata = metadata.to_xml
    record.save!
    metadata
  end

  def metadata_for(entity_id)
    Metadatum.find_by!(issuer: entity_id).to_saml
  rescue ActiveRecord::RecordNotFound => error
    Rails.logger.error(error)
    nil
  end
end
