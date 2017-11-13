class UrlBuilder
  def http_redirect_url_for(uri, saml_request, relay_state)
    uri.to_s + '?' + {
      'SAMLRequest' => saml_request,
      'RelayState' => relay_state,
    }.map do |(x, y)|
      "#{x}=#{CGI.escape(y)}"
    end.join('&')
  end
end
