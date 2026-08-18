# frozen_string_literal: true

module Saml
  module Kit
    # This class is responsible for deciding whether an xml digital signature
    # actually covers the element it is attached to.
    #
    # A cryptographically intact signature only proves that *some* element in
    # the document is unmodified. xmldsig resolves a Reference by searching the
    # whole document for a matching ID, so without this check an attacker can
    # copy a valid signature onto a forged element and hide the element it
    # really covers somewhere the schema still permits, e.g. saml:Advice or
    # ds:Object.
    class SignatureReference
      # The id_attr handed to Xmldsig::Signature, which expands it into
      # "//*[@ID=$uri or @Id=$uri]". Both resolvers must agree on this or the
      # element we check is not the element that was digested.
      ID_ATTR = 'ID=$uri or @Id'
      XPATH = './ds:SignedInfo/ds:Reference'

      def initialize(node)
        @node = node
      end

      # Returns true when some Reference resolves to the element the signature
      # hangs off, and resolves to nothing else.
      #
      # Every Reference lives inside ds:SignedInfo, which ds:SignatureValue
      # covers, so an attacker replaying a signature cannot add a Reference or
      # retarget an existing one. Finding our element among them is therefore
      # enough. SAML 2.0 core 5.4.2 permits only one, but documents carrying
      # more exist, and each extra Reference only widens what the signature
      # already commits to.
      def bound?
        return @bound if defined?(@bound)

        @bound = binds_parent_element?
      end

      private

      attr_reader :node

      def binds_parent_element?
        return false if node.nil? || signed.nil?

        references.any? { |reference| covers_signed_element?(reference) }
      end

      def covers_signed_element?(reference)
        uri = reference.attribute('URI').try(:value).to_s
        # An empty URI digests the whole document, so it covers every element in
        # it and leaves nowhere to hide an original.
        return true if uri.empty?

        id.present? && uri == "##{id}" && resolves_to_signed_element?
      end

      # `bound?` memoizes the one answer this class exists to give, so only the
      # XPath search below is worth caching; the rest are O(1) node lookups.
      def signed
        node.parent
      end

      def references
        @references ||= node.search(XPATH, Saml::Kit::Document::NAMESPACES)
      end

      def id
        signed.attribute('ID').try(:value) || signed.attribute('Id').try(:value)
      end

      # Duplicate IDs are only rejected when schema validation runs, and an
      # XPath lookup silently returns the first match, so require exactly one.
      def resolves_to_signed_element?
        matches = node.document.xpath(
          "//*[@#{ID_ATTR}=$uri]",
          Saml::Kit::Document::NAMESPACES,
          'uri' => id
        )
        matches.count == 1 && matches.first == signed
      end
    end
  end
end
