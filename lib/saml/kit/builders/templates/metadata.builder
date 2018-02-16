xml.instruct!
xml.EntityDescriptor entity_descriptor_options do
  signature_for(reference_id: id, xml: xml)
  render identity_provider, xml: xml
  render service_provider, xml: xml
  xml.Organization do
    xml.OrganizationName organization_name, 'xml:lang': 'en'
    xml.OrganizationDisplayName organization_name, 'xml:lang': 'en'
    xml.OrganizationURL organization_url, 'xml:lang': 'en'
  end
  xml.ContactPerson contactType: 'technical' do
    xml.Company "mailto:#{contact_email}"
  end
end
