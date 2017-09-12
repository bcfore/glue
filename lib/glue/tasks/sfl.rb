require 'glue/tasks/base_task'
require 'json'
require 'glue/util'
require 'find'

class Glue::SFL < Glue::BaseTask

  Glue::Tasks.add self
  include Glue::Util

  PATTERNS_FILE_PATH = File.join(File.dirname(__FILE__), "patterns.json")

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
    begin
      Glue.notify "#{@name}"
      run_sfl
    rescue StandardError => e
      log_error(e)
    end

    self
  end

  def analyze
    @results.each do |result|
      begin
        pattern = result[:pattern]
        filepath = result[:filepath]

        description = pattern['caption']
        detail = pattern['description']
        source = "#{@name}:#{filepath}"
        severity = 'unknown'
        fprint = fingerprint("#{pattern['part']}#{pattern['type']}#{pattern['pattern']}#{filepath}")

        report description, detail, source, severity, fprint
      rescue StandardError => e
        log_error(e)
      end
    end

    self
  end

  def supported?
    true
  end

  private

  def run_sfl
    files = Find.find(@trigger.path).select { |path| File.file?(path) }
    Glue.debug "Found #{files.count} files"

    files.each do |filepath|
      patterns.each do |pattern|
        @results << create_result(filepath, pattern) if matches?(filepath, pattern)
      end
    end

    nil
  end

  def create_result(filepath, pattern)
    {
      filepath: filepath,
      pattern: pattern
    }
  end

  def matches?(filepath, pattern)
    text = extract_filepart(filepath, pattern)
    pattern_matched?(text, pattern)
  end

  def extract_filepart(filepath, pattern)
    # TODO: how to handle the 'else'?
    case pattern['part']
      when 'filename'   then File.basename(filepath)
      when 'extension'  then File.extname(filepath).gsub(/^\./, '')
      when 'path'       then filepath
      else ''
    end
  end

  def pattern_matched?(text, pattern)
    case pattern['type']
      when 'match'
        text == pattern['pattern']
      when 'regex'
        regex = Regexp.new(pattern['pattern'], Regexp::IGNORECASE)
        !!regex.match(text)
      else
        false
    end
  end

  def patterns
    @@patterns ||= read_patterns_file
  end

  def read_patterns_file
    JSON.parse(File.read(PATTERNS_FILE_PATH))
  rescue
    # This re-raises the error (stored in $!) appending some info to the msg
    raise $!, "#{$!} (problem with SFL patterns file)", $!.backtrace
  end

  def log_error(e)
    Glue.notify "Problem running SFL"
    Glue.warn e.inspect
    Glue.warn e.backtrace
  end
end
