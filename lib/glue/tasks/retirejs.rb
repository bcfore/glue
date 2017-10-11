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

  def get_name_version_combos(results)
    name_version_combos = []
    names = JsonPath.on(results, '$..component').uniq

    names.each do |name|
      filter_versions = "$..results[?(@.component == \'#{name}\')].version"
      versions = JsonPath.on(results, filter_versions).uniq
      new_combos = versions.map { |version| [name, version] }
      name_version_combos.concat(new_combos)
    end

    name_version_combos
  end

  def filter_results(results, name, version)
    name_filter = "$..results[?(@.component == \'#{name}\')]"
    by_name = JsonPath.on(results, name_filter)

    by_name_and_version = by_name.select do |result|
      result['version'] == version
    end.uniq

    by_name_and_version
  end

  def package_tag(result)
    name = result['component']
    version = result['version']
    "#{name}-#{version}"
  end

  def vulnerability_hashes(proto_result, source_tag)
    proto_result['vulnerabilities'].each_with_object([]) do |vuln, vulns|
      vuln_hash = {
        package: package_tag(proto_result),
        source: { scanner: @name, file: source_tag, line: nil, code: nil },
        severity: severity(vuln['severity']),
        detail: vuln['info'].join("\n")
      }
      vulns << vuln_hash
    end
  end

  def get_js_vulnerabilities(results)
    main_result = results.first

    comp = main_result['component']
    version = main_result['version']
    package = "#{comp}-#{version}"

    source = { scanner: @name, file: 'xxx', line: nil, code: nil }

    # pull detail/severity
    main_result['vulnerabilities'].each_with_object([]) do |vuln, vulns|
      vuln_hash = {
        package: package,
        source: source,
        severity: severity(vuln['severity']),
        detail: vuln['info'].join("\n")
      }
      vulns << vuln_hash.dup
    end
  end

  def npm_dependency_maps(package_results)
    comp = package_results.first['component']
    version = package_results.first['version']
    maps = []

    package_results.each do |package|
      deps = []
      nested_comp = package

      while nested_comp['parent']
        deps << nested_comp['parent']['component']
        nested_comp = nested_comp['parent']
      end

      if deps.length > 0
        map = "#{deps.reverse.join('->')}->#{comp}-#{version}"
        maps << map
      end
    end

    maps.join("\n")
  end

  def npm_vulnerabilities(results)
    findings = []
    names_versions = get_name_version_combos(results)

    names_versions.each do |name, version|
      filtered = filter_results(results, name, version)
      proto_result = filtered.first

      source_tag = npm_dependency_maps(filtered)
      curr_findings = vulnerability_hashes(proto_result, source_tag)

      findings.concat(curr_findings)
    end

    findings
  end

  def js_vulnerabilities(results)
    get_name_version_combos(js_results).each do |name, version|
      uniq_results = filter_results(raw_results, name, version)
      vulns = get_js_vulnerabilities(uniq_results)
      vulnerabilities.concat(vulns)
    end

    # # Loop through the separately reported 'file' findings
    # # so we can tag the source (no dep map here)
    # raw_results.select { |r| !r['file'].nil? }.each do |file_result|
    #   JsonPath.on(file_result, '$..component').uniq.each do |comp|
    #     JsonPath.on(file_result, "$..results[?(@.component == \'#{comp}\')].version").uniq.each do |version|
    #       # source_path = relative_path(file_result['file'], @trigger.path)
    #       source_path = relative_path(file_result['file'], File.expand_path(@trigger.path))

    #       vulnerabilities.select { |v| v[:package] == "#{comp}-#{version}" }.first[:source] = { :scanner => @name, :file => source_path.to_s, :line => nil, :code => nil }
    #     end
    #   end
    # end
  end

  def parse_retire_json(raw_results)
    Glue.debug "Retire JSON Raw Result:  #{raw_results}"

    js_results, npm_results = raw_results.partition do |result|
      result.has_key?('file')
    end

    js_vulnerabilities(js_results) + npm_vulnerabilities(npm_results)
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

