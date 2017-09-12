require 'spec_helper'

require 'glue'
require 'glue/event'
require 'glue/tracker'
require 'glue/tasks'
require 'glue/tasks/sfl'

# # TODO?: Move this to spec/spec_helper.rb:
# RSpec.configure do |config|
#   config.mock_with :rspec do |mocks|
#     mocks.verify_partial_doubles = true
#   end
# end

describe Glue::SFL do
  # Run 'spec/tasks/snyk/generate_reports.sh' to generate the reports
  # for any new 'targets' you want to test against.
  SFL_TARGETS_PATH = 'spec/tasks/sfl/targets'

  def get_sfl(target = 'nil_target')
    trigger = Glue::Event.new(target)
    trigger.path = File.join(SFL_TARGETS_PATH, target)
    tracker = Glue::Tracker.new({})
    Glue::SFL.new(trigger, tracker)
  end

  # def get_raw_report(target, subtarget = nil)
  #   path = File.join(get_target_path(target, subtarget), "report.json")
  #   File.read(path).chomp
  # end

  # def get_target_path(target, subtarget = nil)
  #   if subtarget.nil?
  #     File.join(SNYK_TARGETS_PATH, target)
  #   else
  #     File.join(SNYK_TARGETS_PATH, target, subtarget)
  #   end
  # end

  describe "#initialize" do
    let(:task) { @task }
    before(:all) { @task = get_sfl }

    it "sets the correct 'name'" do
      expect(task.name).to eq('SFL')
    end

    it "sets the correct 'stage'" do
      expect(task.stage).to eq(:code)
    end

    it "sets the correct 'labels'" do
      expect(task.labels).to eq(%w(code).to_set)
    end
  end

  describe "#supported?" do
    # Since the analysis is built in to Glue (ie, not an external tool)
    # the '.supported?' method should always return 'true'.
    subject(:task) { get_sfl }
    it { is_expected.to be_supported }
  end

  describe "#run" do
    let(:task) { get_sfl target }
    before { allow(Glue).to receive(:notify) } # stub to prevent printing to scree

    context "with an invalid path to the patterns file" do
      def invalidate_patterns_path
        @patterns_path = Glue::SFL::PATTERNS_FILE_PATH.dup
        Glue::SFL::PATTERNS_FILE_PATH.replace 'non-existent-path'
      end

      def restore_patterns_path
        Glue::SFL::PATTERNS_FILE_PATH.replace @patterns_path
      end

      let(:target) { 'no_findings' }

      before { allow(Glue).to receive(:warn) }

      before(:all) { invalidate_patterns_path }
      after(:all) { restore_patterns_path }

      it "handles (does not raise) the error" do
        expect { task.run }.not_to raise_error
      end

      it "issues a notification matching 'Problem running SFL'" do
        expect(Glue).to receive(:notify).with(/Problem running SFL/)
        task.run rescue nil
      end

      it "issues a warning matching 'Err'" do
        expect(Glue).to receive(:warn).with(/Err/)
        task.run rescue nil
      end
    end

    context "in a general context" do
      let(:target) { 'no_findings' }

      it "passes the task name to Glue.notify" do
        expect(Glue).to receive(:notify).with(/^SFL/)
        task.run
      end

      it "returns 'self'" do
        expect(task.run).to be(task)
      end
    end
  end

  describe "#analyze" do
    let(:task) { get_sfl target }

    before do
      allow(Glue).to receive(:notify) # stub to prevent printing to scree
      task.run
      task.analyze
    end

    context "on an empty dir" do
      let(:target) { 'no_findings_empty_dir' }
      subject(:task_findings) { task.findings }
      it { is_expected.to eq([]) }
    end

    context "on a dir with no findings" do
      let(:target) { 'no_findings' }
      subject(:task_findings) { task.findings }
      it { is_expected.to eq([]) }
    end

    context "with one finding" do
      # Doesn't seem necessary to check the 'finding' details
      # in every case here, so it's only done once.
      #
      # The main point is to make sure the different types of
      # patterns all work.

      subject(:findings_count) { task.findings.size }

      context "on an extension exact match" do
        let(:target) { 'one_finding_extension_match' }
        it { is_expected.to eq(1) }
      end

      context "on an extension regex match" do
        let(:target) { 'one_finding_extension_regex' }
        it { is_expected.to eq(1) }
      end

      context "on a path regex match" do
        let(:target) { 'one_finding_path_regex' }
        it { is_expected.to eq(1) }
      end

      context "on a filename regex match" do
        let(:target) { 'one_finding_filename_regex' }
        it { is_expected.to eq(1) }
      end

      context "on a filename exact match" do
        # The filename here is 'secret_token.rb'.
        let(:target) { 'one_finding_filename_match' }
        let(:filepath) { File.join(SFL_TARGETS_PATH, target, 'secret_token.rb') }
        let(:the_pattern) {
          # Copy-pasted from the patterns file:
          {
            "part": "filename",
            "type": "match",
            "pattern": "secret_token.rb",
            "caption": "Ruby On Rails secret token configuration file",
            "description": "If the Rails secret token is known, it can allow for remote code execution. (http://www.exploit-db.com/exploits/27527/)"
          }
        }
        let(:finding) { task.findings.first }

        it { is_expected.to eq(1) }

        it "has the correct 'finding' descriptors" do
          expect(finding.task).to eq("SFL")
          expect(finding.appname).to eq(target)
          expect(finding.description).to eq(the_pattern[:caption])
          expect(finding.detail).to eq(the_pattern[:description])
        end

        it "has the filepath in its 'source'" do
          expect(finding.source).to match(filepath)
        end

        it "has the expected fingerprint" do
          the_fingerprint = task.fingerprint("#{the_pattern[:part]}#{the_pattern[:type]}#{the_pattern[:pattern]}#{filepath}")

          expect(finding.fingerprint).to eq(the_fingerprint)
        end
      end
    end

    context "with two findings" do
      subject(:findings_count) { task.findings.size }

      context "in the same dir" do
        let(:target) { 'two_findings' }
        it { is_expected.to eq(2) }
      end

      context "in different dirs" do
        let(:target) { 'two_findings_difft_dirs' }
        it { is_expected.to eq(2) }
      end
    end
  end
end
