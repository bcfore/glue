require 'glue/tasks/base_task'
require 'json'
require 'glue/util'
require 'jsonpath'
require 'pathname'

class Glue::RetireJS < Glue::BaseTask
  Glue::Tasks.add self
  include Glue::Util

  SUPPORTED_CHECK_STR = "retire --help"
  BASE_EXCLUDE_DIRS = %w(node_modules bower_components).freeze

  def initialize(trigger, tracker)
    super(trigger, tracker)
    @name = "RetireJS"
    @description = "Dependency analysis for JavaScript"
    @stage = :code
    @labels << "code" << "javascript"
    @results = []
    self
  end

  def run
    directories_with?('package.json', exclude_dirs).each do |dir|
      Glue.notify "#{@name} scanning: #{dir}"
      command_line = "retire -c --outputpath /dev/stdout " \
        "--outputformat json --path #{dir}"
      raw_output = runsystem(true, command_line)
      @results << raw_output
    end

    self
  end

  def analyze
    @results.each do |result|
      begin
        parsed_json = JSON.parse(result)
        vulnerabilities = parse_retire_json(parsed_json) if parsed_json

        vulnerabilities.each do |vuln|
          description ="Package #{vuln[:package]} has known security issues"
          detail = vuln[:detail]
          source = vuln[:source]
          sev = vuln[:severity]
          fprint = fingerprint("#{vuln[:package]}#{source}#{sev}")

          report description, detail, source, sev, fprint
        end
      rescue StandardError => e
        log_error(e)
      end
    end

    self
  end

  def supported?
    runsystem(false, SUPPORTED_CHECK_STR)
    true
  rescue Errno::ENOENT # gets raised if the command isn't found
    Glue.notify "Install RetireJS: 'npm install -g retire'"
    false
  end

  private

  def exclude_dirs
    extra_exclude_dirs = @tracker.options[:exclude_dirs] || []
    BASE_EXCLUDE_DIRS | extra_exclude_dirs
  end

  def get_package_results(result)
    package_names = JsonPath.on(result, '$..component').uniq

    package_names.each do |package_name|
      package_versions = JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')].version").uniq

      package_versions.each do |version|

        package_results = JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')]").select { |r| r['version'] == version }.uniq

  end

  def parse_retire_json(result)
    Glue.debug "Retire JSON Raw Result:  #{result}"
    vulnerabilities = []
    # This is very ugly, but so is the json retire.js spits out
    # Loop through each component/version combo and pull all results for it
    JsonPath.on(result, '$..component').uniq.each do |comp|
      JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')].version").uniq.each do |version|
        vuln_hash = {}
        vuln_hash[:package] = "#{comp}-#{version}"

        package_results = JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')]").select { |r| r['version'] == version }.uniq

        # If we see the parent-->component relationship, dig through the dependency tree to try and make a dep map
        deps = []
        obj = package_results[0]
        while !obj['parent'].nil?
          deps << obj['parent']['component']
          obj = obj['parent']
        end
        if deps.length > 0
          vuln_hash[:source] = { :scanner => @name, :file => "#{deps.reverse.join('->')}->#{comp}-#{version}", :line => nil, :code => nil }
        end

        vuln_hash[:severity] = 'unknown'
        # pull detail/severity
        package_results.each do |version_result|
          JsonPath.on(version_result, '$..vulnerabilities').uniq.each do |vuln|
            vuln_hash[:severity] = severity(vuln[0]['severity'])
            vuln_hash[:detail] = vuln[0]['info'].join('\n')
          end
        end

        vulnerabilities << vuln_hash
      end
    end

    # Loop through the separately reported 'file' findings so we can tag the source (no dep map here)
    result.select { |r| !r['file'].nil? }.each do |file_result|
      JsonPath.on(file_result, '$..component').uniq.each do |comp|
        JsonPath.on(file_result, "$..results[?(@.component == \'#{comp}\')].version").uniq.each do |version|
          source_path = relative_path(file_result['file'], @trigger.path)
          vulnerabilities.select { |v| v[:package] == "#{comp}-#{version}" }.first[:source] = { :scanner => @name, :file => source_path.to_s, :line => nil, :code => nil }
        end
      end
    end
    return vulnerabilities
  end

  def log_error(e)
    Glue.notify "Problem running RetireJS"
    Glue.warn e.inspect
    Glue.warn e.backtrace
  end
end

# Here is the initial version of the parsing method.
# It was called from analyze:
#   parsed_json = JSON.parse(result)
#   vulnerabilities = parse_retire_json(parsed_json) if parsed_json
#
  # def parse_retire_json result
  #   Glue.debug "Retire JSON Raw Result:  #{result}"
  #   vulnerabilities = []
  #   # This is very ugly, but so is the json retire.js spits out
  #   # Loop through each component/version combo and pull all results for it
  #   JsonPath.on(result, '$..component').uniq.each do |comp|
  #     JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')].version").uniq.each do |version|
  #       vuln_hash = {}
  #       vuln_hash[:package] = "#{comp}-#{version}"

  #       version_results = JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')]").select { |r| r['version'] == version }.uniq

  #       # If we see the parent-->component relationship, dig through the dependency tree to try and make a dep map
  #       deps = []
  #       obj = version_results[0]
  #       while !obj['parent'].nil?
  #         deps << obj['parent']['component']
  #         obj = obj['parent']
  #       end
  #       if deps.length > 0
  #         vuln_hash[:source] = { :scanner => @name, :file => "#{deps.reverse.join('->')}->#{comp}-#{version}", :line => nil, :code => nil }
  #       end

  #       vuln_hash[:severity] = 'unknown'
  #       # pull detail/severity
  #       version_results.each do |version_result|
  #         JsonPath.on(version_result, '$..vulnerabilities').uniq.each do |vuln|
  #           vuln_hash[:severity] = severity(vuln[0]['severity'])
  #           vuln_hash[:detail] = vuln[0]['info'].join('\n')
  #         end
  #       end

  #       vulnerabilities << vuln_hash
  #     end
  #   end

  #   # Loop through the separately reported 'file' findings so we can tag the source (no dep map here)
  #   result.select { |r| !r['file'].nil? }.each do |file_result|
  #     JsonPath.on(file_result, '$..component').uniq.each do |comp|
  #       JsonPath.on(file_result, "$..results[?(@.component == \'#{comp}\')].version").uniq.each do |version|
  #         source_path = relative_path(file_result['file'], @trigger.path)
  #         vulnerabilities.select { |v| v[:package] == "#{comp}-#{version}" }.first[:source] = { :scanner => @name, :file => source_path.to_s, :line => nil, :code => nil }
  #       end
  #     end
  #   end
  #   return vulnerabilities
  # end

