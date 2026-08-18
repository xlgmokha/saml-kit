# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for validating
    # xml documents against the SAML XSD's
    module XsdValidatable
      PROTOCOL_XSD = File.expand_path(
        '../xsd/saml-schema-protocol-2.0.xsd', File.dirname(__FILE__)
      ).freeze

      METADATA_XSD = File.expand_path(
        '../xsd/saml-schema-metadata-2.0.xsd', File.dirname(__FILE__)
      ).freeze

      @schemas = {}
      @monitor = Mutex.new

      class << self
        # Validation treats a schema as read only, so one instance is shared
        # across threads. The hit path reads without the lock, which at worst
        # compiles the same schema twice on rubies that lack a global lock.
        #
        # @!visibility private
        def schema_for(path)
          @schemas[path] || @monitor.synchronize do
            @schemas[path] ||= compile(path)
          end
        end

        private

        # The xsd is parsed as a document carrying its own path as a base uri,
        # so the relative schemaLocation imports in our xsds resolve against
        # the xsd's own directory. A bare String carries no base uri and would
        # resolve them against the working directory instead, which is what
        # Dir.chdir used to paper over at the cost of crashing under threads.
        def compile(path)
          Nokogiri::XML::Schema.from_document(
            Nokogiri::XML::Document.parse(File.read(path), url: path)
          )
        end
      end

      # @!visibility private
      def matches_xsd?(path)
        return unless to_nokogiri.present?

        schema = XsdValidatable.schema_for(path)
        schema.validate(to_nokogiri.document).each do |error|
          errors.add(:base, error.message)
        end
      end
    end
  end
end
