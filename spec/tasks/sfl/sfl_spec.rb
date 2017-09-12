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
    # The analysis is built in to Glue, it's not an external tool.
    # So '.supported?' should always return 'true'.
    subject(:task) { get_sfl }
    it { is_expected.to be_supported }
  end

  describe "#run" do
    let(:task) { get_sfl target }

    context "with an invalid path to the patterns file" do

    end

    context "in a general context" do
      let(:target) { 'no_findings' }

      it "passes the task name to Glue.notify" do
        expect(Glue).to receive(:notify).with(/^SFL/)
        task.run
      end
    end
  end
end
