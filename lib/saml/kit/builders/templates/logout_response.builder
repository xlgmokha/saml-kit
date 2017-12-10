xml.LogoutResponse logout_response_options do
  xml.Issuer(issuer, xmlns: Saml::Kit::Namespaces::ASSERTION)
  signature.template(id)
  xml.Status do
    xml.StatusCode Value: status_code
  end
end
