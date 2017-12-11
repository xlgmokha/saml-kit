xml.instruct!
xml.LogoutResponse logout_response_options do
  xml.Issuer(issuer, xmlns: Saml::Kit::Namespaces::ASSERTION)
  signature_for(reference_id: id, xml: xml)
  xml.Status do
    xml.StatusCode Value: status_code
  end
end
