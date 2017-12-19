# Saml::Kit

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. 
Put your Ruby code in the file `lib/saml/kit`. To experiment with that code, run `bin/console` for an interactive prompt.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'saml-kit'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install saml-kit

## Usage

To specify a global configuration: (useful for a rails application)

```ruby
Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  configuration.generate_key_pair_for(use: :signing)
  configuration.generate_key_pair_for(use: :signing)
end
```

### Metadata

To generate metadata for an Identity Provider.

```ruby
Saml::Kit::Metadata.build_xml do |builder|
  builder.contact_email = 'hi@example.com'
  builder.organization_name = "Acme, Inc"
  builder.organization_url = 'https://www.example.com'
  builder.build_identity_provider do |x|
    x.add_single_sign_on_service('https://www.example.com/login', binding: :http_post)
    x.add_single_sign_on_service('https://www.example.com/login', binding: :http_redirect)
    x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
    x.name_id_formats = [ Saml::Kit::Namespaces::EMAIL_ADDRESS ]
    x.attributes << :id
    x.attributes << :email
  end
end
```

Will produce something like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_efe0c000-8d0d-4406-96b8-61f649e004f6" entityID="">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/logout"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/login"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://www.example.com/login"/>
    <saml:Attribute Name="id"/>
    <saml:Attribute Name="email"/>
  </IDPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Acme, Inc</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Acme, Inc</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://www.example.com</OrganizationURL>
  </Organization>
  <ContactPerson contactType="technical">
    <Company>mailto:hi@example.com</Company>
  </ContactPerson>
</EntityDescriptor>
```

To generate service provider metadata:

```xml
metadata = Saml::Kit::Metadata.build do |builder|
  builder.contact_email = 'hi@example.com'
  builder.organization_name = "Acme, Inc"
  builder.organization_url = 'https://www.example.com'
  builder.build_service_provider do |x|
    x.add_assertion_consumer_service('https://www.example.com/consume', binding: :http_post)
    x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
  end
end
puts metadata.to_xml(pretty: true)
```

Will produce something like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_3ff5e4b3-4fce-4cc9-b278-6cb3a0a8cb10" entityID="">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/logout"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/consume" index="0" isDefault="true"/>
  </SPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Acme, Inc</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Acme, Inc</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://www.example.com</OrganizationURL>
  </Organization>
  <ContactPerson contactType="technical">
    <Company>mailto:hi@example.com</Company>
  </ContactPerson>
</EntityDescriptor>
```

To produce Metadata with an IDPSSODescriptor and SPSSODescriptor.

```ruby
metadata = Saml::Kit::Metadata.build do |builder|
  builder.contact_email = 'hi@example.com'
  builder.organization_name = "Acme, Inc"
  builder.organization_url = 'https://www.example.com'
  builder.build_identity_provider do |x|
    x.add_single_sign_on_service('https://www.example.com/login', binding: :http_post)
    x.add_single_sign_on_service('https://www.example.com/login', binding: :http_redirect)
    x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
    x.name_id_formats = [ Saml::Kit::Namespaces::EMAIL_ADDRESS ]
    x.attributes << :id
    x.attributes << :email
  end
  builder.build_service_provider do |x|
    x.add_assertion_consumer_service('https://www.example.com/consume', binding: :http_post)
    x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
  end
end
puts metadata.to_xml(pretty: true)
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a29a3a9d-ad16-4839-8f5d-a59daed6f3ce" entityID="">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/logout"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/login"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://www.example.com/login"/>
    <saml:Attribute Name="id"/>
    <saml:Attribute Name="email"/>
  </IDPSSODescriptor>
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/logout"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/consume" index="0" isDefault="true"/>
  </SPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Acme, Inc</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Acme, Inc</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://www.example.com</OrganizationURL>
  </Organization>
  <ContactPerson contactType="technical">
    <Company>mailto:hi@example.com</Company>
  </ContactPerson>
</EntityDescriptor>
```

### AuthnRequest

To generate an Authentication Request choose the desired binding from
the metadata and use it to serialize a request.

```ruby
idp = Saml::Kit::IdentityProviderMetadata.new(raw_xml)
url, saml_params = idp.login_request_for(binding: :http_post)
puts [url, saml_params].inspect
# ["https://www.example.com/login", {"SAMLRequest"=>"PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6QXV0aG5SZXF1ZXN0IHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfN2Y0YjkxZGMtNTMyNi00NjgzLTgyOWItYWViNzlkNjM0ZWYzIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNy0xMi0xOVQwNDo0ODoxMloiIERlc3RpbmF0aW9uPSJodHRwczovL3d3dy5leGFtcGxlLmNvbS9sb2dpbiI+PHNhbWw6SXNzdWVyLz48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudCIvPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg=="}]
```

### LogoutRequest

To generate a Response choose the desired binding form the metadata and
use it to serialize a response. You will also need to specify a user
object to create a response for.

```ruby
class User
  attr_reader :id, :email

  def initialize(id:, email:)
    @id = id
    @email = email
  end

  def name_id_for(name_id_format)
    Saml::Kit::Namespaces::PERSISTENT == name_id_format ? id : email
  end

  def assertion_attributes_for(request)
    request.trusted? ? { access_token: SecureRandom.uuid } : {}
  end
end

user = User.new(id: SecureRandom.uuid, email: "hello@example.com")
sp = Saml::Kit::IdentityProviderMetadata.new(xml)
url, saml_params = sp.logout_request_for(user, binding: :http_post)
puts [url, saml_params].inspect
# ["https://www.example.com/logout", {"SAMLRequest"=>"PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48TG9nb3V0UmVxdWVzdCBJRD0iXzg3NjZiNTYyLTc2MzQtNDU4Zi04MzJmLTE4ODkwMjRlZDQ0MyIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTctMTItMTlUMDQ6NTg6MThaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vbG9nb3V0IiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIi8+PE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5kODc3YWEzZS01YTUyLTRhODAtYTA3ZC1lM2U5YzBjNTA1Nzk8L05hbWVJRD48L0xvZ291dFJlcXVlc3Q+"}]
```


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitLab at https://gitlab.com/xlgmokha/saml-kit.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
