require 'spec_helper'

require 'glue'
require 'glue/event'
require 'glue/tracker'
require 'glue/tasks'
require 'glue/tasks/retirejs'

# # TODO?: Move this to spec/spec_helper.rb:
RSpec.configure do |config|
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
end

describe Glue::RetireJS do
  # Run 'spec/tasks/retirejs/generate_reports.sh' to generate the reports
  # for any new 'targets' you want to test against.
  RETIREJS_TARGETS_PATH = 'spec/tasks/retirejs/targets'

  def get_retirejs(target = 'nil_target')
    trigger = Glue::Event.new(target)
    trigger.path = File.join(RETIREJS_TARGETS_PATH, target)
    tracker = Glue::Tracker.new({})
    Glue::RetireJS.new(trigger, tracker)
  end

  def set_exclude_dir!(task, dir)
    tracker = task.instance_variable_get(:@tracker)
    tracker.options[:exclude_dirs] ||= []
    tracker.options[:exclude_dirs] << dir
  end

  # def get_raw_report(target, subtarget = nil)
  #   path = File.join(get_target_path(target, subtarget), "report.json")
  #   File.read(path).chomp
  # end

  def get_target_path(target, subtarget = nil)
    if subtarget.nil?
      File.join(RETIREJS_TARGETS_PATH, target)
    else
      File.join(RETIREJS_TARGETS_PATH, target, subtarget)
    end
  end

  def cli_args(target, subtarget = nil)
    [ true,
      'retire',
      '-c',
      '--outputpath',
      '/dev/stdout',
      '--outputformat',
      'json',
      '--path',
      get_target_path(target, subtarget)
    ]
  end

  describe "#initialize" do
    let(:task) { @task }
    before(:all) { @task = get_retirejs }

    it "sets the correct 'name'" do
      expect(task.name).to eq('RetireJS')
    end

    it "sets the correct 'stage'" do
      expect(task.stage).to eq(:code)
    end

    it "sets the correct 'labels'" do
      expect(task.labels).to eq(%w(code javascript).to_set)
    end
  end

  describe "#supported?" do
    subject(:task) { get_retirejs }

    context "when 'runsystem' cannot run the task" do
      def invalidate_task_name
        @orig_task = Glue::RetireJS::SUPPORTED_CHECK_STR.dup
        Glue::RetireJS::SUPPORTED_CHECK_STR.replace "does/not/exist"
      end

      def restore_task_name
        Glue::RetireJS::SUPPORTED_CHECK_STR.replace @orig_task
      end

      before(:each) { allow(Glue).to receive(:notify) } # suppress the output
      before(:all) { invalidate_task_name }
      after(:all) { restore_task_name }

      it { is_expected.not_to be_supported }

      it "issues a notification" do
        expect(Glue).to receive(:notify)
        task.supported?
      end
    end

    context "when 'runsystem' returns a help-type message" do
      before do
        help_args = [anything, Glue::RetireJS::SUPPORTED_CHECK_STR]
        help_str = "Usage: retire [options]"
        allow(task).to receive(:runsystem).with(*help_args).and_return(help_str)
      end

      it { is_expected.to be_supported }
    end
  end

  describe "#run" do
    let(:task) { get_retirejs target }
    let(:minimal_response) { "[]" }

    before do
      allow(Glue).to receive(:notify) # suppress the output
    end

    context "with no package.json file in root, and no sub-dirs" do
      let(:target) { 'no_findings_no_package_json' }

      it "does not call the 'retire' cli on the target" do
        expect(task).not_to receive(:runsystem).with(*cli_args(target))
        task.run
      end
    end

    context "assuming valid (but minimal) reports" do
      # Expectations like the following:
      #
      #   expect(task).to receive(:runsystem).with(*cli_args(target)).and_return(minimal_response)
      #   task.run
      #
      # can be read as:
      # 'When we call task.run, we expect it to call:
      #    runsystem(true, "retire", "-c", ..., "--path", <target>)
      #  When it does, have it return a canned response,
      #  instead of the default response for stubbed methods (nil).'
      #  Ie, the response is not part of the expectation.
      #  It's needed, b/c without it 'runsystem' will return nil,
      #  and task.run may raise an exception
      #  (since it expects a non-nil response).

      context "with one package.json in the root dir" do
        let(:target) { 'finding_1' }

        it "passes the task name to Glue.notify" do
          allow(task).to receive(:runsystem).with(*cli_args(target)).and_return(minimal_response)
          expect(Glue).to receive(:notify).with(/^RetireJS/)
          task.run
        end

        it "calls the 'retire' cli once, from the root dir" do
          expect(task).to receive(:runsystem).with(*cli_args(target)).and_return(minimal_response)
          task.run
        end
      end

      context "with one package.json in a sub-dir" do
        let(:target) { 'finding_1_nested' }
        let(:subtarget) { 'finding_1' }

        it "calls the 'retire' cli once, from the sub-dir" do
          expect(task).to receive(:runsystem).with(*cli_args(target, subtarget)).and_return(minimal_response)
          task.run
        end
      end

      context "with three package.json files in different sub-dirs" do
        let(:target) { 'findings_1_2_3' }
        let(:subtargets) { [1, 2, 3].map { |i| "finding_#{i}" } }

        context "and no excluded dirs" do
          it "calls the 'retire' cli from each sub-dir" do
            subtargets.each do |subtarget|
              expect(task).to receive(:runsystem).with(*cli_args(target, subtarget)).and_return(minimal_response)
            end
            task.run
          end
        end

        context "and one excluded dir" do
          it "only calls the 'retire' cli from the non-excluded dirs" do
            set_exclude_dir!(task, subtargets[1])

            expect(task).not_to receive(:runsystem).with(*cli_args(target, subtargets[1]))
            expect(task).to receive(:runsystem).with(*cli_args(target, subtargets[0])).and_return(minimal_response)
            expect(task).to receive(:runsystem).with(*cli_args(target, subtargets[2])).and_return(minimal_response)

            task.run
          end
        end

        context "and all dirs excluded" do
          it "does not call the 'retire' cli on the dirs" do
            subtargets.each do |subtarget|
              set_exclude_dir!(task, subtarget)
              expect(task).not_to receive(:runsystem).with(*cli_args(target, subtarget))
            end

            task.run
          end
        end
      end
    end

    context "with a malformed report" do
      # The expected report format is a JSON-ified array, possibly empty.
      # But the 'run' method simply stores the raw output, it doesn't
      # do any parsing, so it won't raise anyway.

      let(:target) { 'malformed' }
      let(:malformed_response) { 'An example error message.' }

      before do
        allow(task).to receive(:runsystem).with(*cli_args(target)).and_return(malformed_response)
      end

      it "does not raise an exception" do
        expect { task.run }.not_to raise_error
      end
    end
  end

  describe "#analyze" do
    let(:task) { get_retirejs target }
    let(:minimal_response) { "[]" }

    before do
      allow(Glue).to receive(:notify) # suppress the output

      # # This acts as a guard aginst actually calling the task from the CLI.
      # # (All specs should use canned responses instead.)
      # allow(task).to receive(:runsystem) do
      #   puts "Warning from rspec -- make sure you're not attempting to call the actual Snyk API"
      #   puts "within an 'it' block with description '#{self.class.description}'"
      #   minimal_response
      # end
    end

    context "with no package.json file in root, and no sub-dirs" do
      let(:target) { 'no_findings_no_package_json' }
      subject(:task_findings) { task.findings }
      it { is_expected.to eq([]) }
    end
  end
end
