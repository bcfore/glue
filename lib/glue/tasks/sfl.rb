require 'glue/tasks/base_task'
require 'json'
require 'glue/util'
require 'find'

class Glue::SFL < Glue::BaseTask

  Glue::Tasks.add self
  include Glue::Util

  # PATTERNS_FILE_PATH = File.join(File.dirname(__FILE__), "patterns.json")
  PATTERNS_FILE_PATH = File.join("spec/tasks/sfl", "malformed_patterns_file.json")

  def initialize(trigger, tracker)
    super(trigger, tracker)
    @name = "SFL"
    @description = "Sensitive File Lookup (SFL)"
    @stage = :code
    @labels << "code"
    @results = []
    self
  end

  def run
    Glue.notify "#{@name}"
    run_sfl
  rescue StandardError => e
    log_error(e)
  ensure
    self
  end

  def analyze
    begin
    rescue Exception => e
      Glue.warn e.message
    end
  end

  def supported?
    true
  end

  private

  def run_sfl
    files = Find.find(@trigger.path).select { |path| File.file?(path) }
    Glue.debug "Found #{files.count} files"

    files.each do |file|
      # TODO?: Change to patterns.find ? Or do we expect more than one match?
      patterns.each do |pattern|
        @results << create_result(file, pattern) if matches?(file, pattern)
      end
    end
    patterns
  end

  def create_result(file, pattern)

  end

  def matches?(file, pattern)
    text = case pattern['part']
      when 'filename'   then File.basename(file)
      when 'extension'  then File.extname(file)
      else '' # TODO: how to handle bad 'pattern' hashes?
    end
      # report pattern['caption'], pattern['description'], @name + ":" + file, 'unknown', 'TBD'

    pattern_matched?(text, pattern)
  end

  def patterns
    @@patterns ||= read_patterns_file
  end

  def read_patterns_file
    JSON.parse(File.read(PATTERNS_FILE_PATH))
  rescue
    raise $!, "#{$!} (problem with SFL patterns file)", $!.backtrace
  # rescue JSON::ParserError => e
  #   Glue.warn "Cannot parse pattern file: #{e.message}"
  end

  def pattern_matched?(txt, pattrn)
    case pattrn['type']
      when 'match'
        return txt == pattrn['pattern']
      when 'regex'
        regex = Regexp.new(pattrn['pattern'], Regexp::IGNORECASE)
        return !regex.match(txt).nil?
    end
  end

  def log_error(e)
    Glue.notify "Problem running SFL"
    Glue.warn e.inspect
    Glue.warn e.backtrace
  end
end
