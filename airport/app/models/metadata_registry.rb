class MetadataRegistry
  def register_url(url, verify_ssl: true)
    content = Saml::Kit::DefaultRegistry::HttpApi.new(url, verify_ssl: verify_ssl).get
    register(Saml::Kit::Metadata.from(content))
  end

  def register(metadata)
    record = Metadatum.find_or_create_by!(issuer, metadata.entity_id)
    record.metadata = metadata.to_xml
    record.save!
    metadata
  end

  def metadata_for(entity_id)
    Saml::Kit::Metadata.from(Metadatum.find_by!(entity_id: entity_id).metadata)
  rescue ActiveRecord::RecordNotFound => error
    Rails.logger.error(error)
    nil
  end
end
