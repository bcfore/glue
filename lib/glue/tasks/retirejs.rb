require 'glue/tasks/base_task'
require 'json'
require 'glue/util'
require 'jsonpath'
require 'pathname'
require 'pry'

class Glue::RetireJS < Glue::BaseTask

  Glue::Tasks.add self
  include Glue::Util

  def initialize(trigger, tracker)
    super(trigger, tracker)
    @name = "RetireJS"
    @description = "Dependency analysis for JavaScript"
    @stage = :code
    @labels << "code" << "javascript"
    @results = []
  end

  def run
    exclude_dirs = ['node_modules','bower_components']
    exclude_dirs = exclude_dirs.concat(@tracker.options[:exclude_dirs]).uniq if @tracker.options[:exclude_dirs]
    directories_with?('package.json', exclude_dirs).each do |dir|
      Glue.notify "#{@name} scanning: #{dir}"
      # @results << runsystem(false, 'retire', '-c', '--outputformat', 'json', '--path', "#{dir}")
      @results << runsystem(true, 'retire', '-c', '--outputformat', 'json', '--path', "#{dir}")
      # begin
      #   @results << runsystem(true, 'retire', '-c', '--outputformat', 'json', '--path', "#{dir}", {STDERR=>STDOUT, STDOUT=>STDERR})
      # rescue Exception => e
      #   Glue.notify e.inspect
      # end
      # @results << runsystem(true, 'retire', '-c', '--outputformat', 'json', '--path', "#{dir}", :err => :out)
      # binding.pry
    end
  end

  def analyze
    # bcf -
    # Doesn't seem to handle the case that there are no issues -- retire returns "", causing
    # the JSON parser to crash here.
    #
    # When there are issues, retire sends them to stderr instead of stdout, and Glue doesn't
    # see them.

    # binding.pry
    begin
      @results.each do |result|
        parsed_json = JSON.parse(result)
        vulnerabilities = parse_retire_json(parsed_json) if parsed_json

        vulnerabilities.each do |vuln|
          report "Package #{vuln[:package]} has known security issues", vuln[:detail], vuln[:source], vuln[:severity], fingerprint("#{vuln[:package]}#{vuln[:source]}#{vuln[:severity]}")
        end
      end
    rescue JSON::ParserError => e
      Glue.notify e.inspect # bcf
      Glue.debug e.message
    rescue Exception => e
      Glue.notify e.inspect # bcf
      Glue.warn e.message
      Glue.warn e.backtrace
    end
  end

  def parse_retire_json result
    Glue.debug "Retire JSON Raw Result:  #{result}"
    vulnerabilities = []
    # This is very ugly, but so is the json retire.js spits out
    # Loop through each component/version combo and pull all results for it
    JsonPath.on(result, '$..component').uniq.each do |comp|
      JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')].version").uniq.each do |version|
        vuln_hash = {}
        vuln_hash[:package] = "#{comp}-#{version}"

        version_results = JsonPath.on(result, "$..results[?(@.component == \'#{comp}\')]").select { |r| r['version'] == version }.uniq

        # If we see the parent-->component relationship, dig through the dependency tree to try and make a dep map
        deps = []
        obj = version_results[0]
        while !obj['parent'].nil?
          deps << obj['parent']['component']
          obj = obj['parent']
        end
        if deps.length > 0
          vuln_hash[:source] = { :scanner => @name, :file => "#{deps.reverse.join('->')}->#{comp}-#{version}", :line => nil, :code => nil }
        end

        vuln_hash[:severity] = 'unknown'
        # pull detail/severity
        version_results.each do |version_result|
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

  def supported?
    # bcf -
    # This doesn't seem to work properly. It throws rather than returning
    # "command not found". Maybe it's better to use findexecutable0?
    # supported=runsystem(false, "retirex", "--help")
    supported=runsystem(false, "retire", "--help")
    if supported =~ /command not found/
      Glue.notify "Install RetireJS"
      return false
    else
      return true
    end
  end

end
