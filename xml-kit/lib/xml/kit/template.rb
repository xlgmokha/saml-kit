module Xml
  module Kit
    class Template
      attr_reader :target

      def initialize(target)
        @target = target
      end

      # Returns the compiled template as a [String].
      #
      # @param options [Hash] The options hash to pass to the template engine.
      def to_xml(options = {})
        template.render(target, options)
      end

      private

      def template_path
        return target.template_path if target.respond_to?(:template_path)

        root_path = File.expand_path(File.dirname(__FILE__))
        template_name = "#{target.class.name.split("::").last.underscore}.builder"
        File.join(root_path, "builders/templates/", template_name)
      end

      def template
        Tilt.new(template_path)
      end
    end
  end
end
