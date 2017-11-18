module Saml
  module Kit
    module Respondable
      def status_code
        to_h.fetch(name, {}).fetch('Status', {}).fetch('StatusCode', {}).fetch('Value', nil)
      end
    end
  end
end
