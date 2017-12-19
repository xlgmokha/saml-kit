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

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitLab at https://gitlab.com/xlgmokha/saml-kit.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
