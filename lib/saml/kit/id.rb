module Saml
  module Kit
    class Id
      def self.generate
        "_#{SecureRandom.uuid}"
      end
    end
  end
end
