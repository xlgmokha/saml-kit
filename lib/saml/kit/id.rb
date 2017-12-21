module Saml
  module Kit
    # This class is used primary for generating ID.
    #https://www.w3.org/2001/XMLSchema.xsd
    class Id

     # Generate an ID that conforms to the XML Schema.
      # https://www.w3.org/2001/XMLSchema.xsd
      def self.generate
        "_#{SecureRandom.uuid}"
      end
    end
  end
end
