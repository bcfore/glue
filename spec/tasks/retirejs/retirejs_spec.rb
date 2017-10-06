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

  def get_raw_report(target, subtarget = nil)
    path = File.join(get_target_path(target, subtarget), "report.json")
    File.read(path).chomp
  end

  def get_target_path(target, subtarget = nil)
    if subtarget.nil?
      File.join(RETIREJS_TARGETS_PATH, target)
    else
      File.join(RETIREJS_TARGETS_PATH, target, subtarget)
    end
  end

  def cli_args(target, subtarget = nil)
    # [ true,
    #   'retire',
    #   '-c',
    #   '--outputpath',
    #   '/dev/stdout',
    #   '--outputformat',
    #   'json',
    #   '--path',
    #   get_target_path(target, subtarget)
    # ]
    #
    command_line = "retire -c --outputpath /dev/stdout " \
      "--outputformat json --path #{get_target_path(target, subtarget)}"
    [ true, command_line ]
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
    # Note that 'runsystem' is always stubbed here (either with
    # 'allow' or 'expect') so the 'retire' cli won't actually be called.

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
      context "with one package.json in the root dir" do
        let(:target) { 'finding_1' }

        before do
          allow(task).to receive(:runsystem).with(*cli_args(target))
        end

        it "passes the task name to Glue.notify" do
          expect(Glue).to receive(:notify).with(/^RetireJS/)
          task.run
        end

        it "calls the 'retire' cli once, from the root dir" do
          expect(task).to receive(:runsystem).with(*cli_args(target))
          task.run
        end

        it "returns 'self'" do
          expect(task.run).to be(task)
        end
      end

      context "with one package.json in a sub-dir" do
        let(:target) { 'finding_1_nested' }
        let(:subtarget) { 'finding_1' }

        it "calls the 'retire' cli once, from the sub-dir" do
          expect(task).to receive(:runsystem).with(*cli_args(target, subtarget))
          task.run
        end
      end

      context "with three package.json files in different sub-dirs" do
        let(:target) { 'findings_1_2_3' }
        let(:subtargets) { [1, 2, 3].map { |i| "finding_#{i}" } }

        context "and no excluded dirs" do
          it "calls the 'retire' cli from each sub-dir" do
            subtargets.each do |subtarget|
              expect(task).to receive(:runsystem).with(*cli_args(target, subtarget))
            end
            task.run
          end
        end

        context "and one excluded dir" do
          it "only calls the 'retire' cli from the non-excluded dirs" do
            set_exclude_dir!(task, subtargets[1])

            expect(task).not_to receive(:runsystem).with(*cli_args(target, subtargets[1]))
            expect(task).to receive(:runsystem).with(*cli_args(target, subtargets[0]))
            expect(task).to receive(:runsystem).with(*cli_args(target, subtargets[2]))

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

      # This acts as a guard aginst actually calling the task from the CLI.
      # (All specs should use canned responses instead.)
      allow(task).to receive(:runsystem) do
        puts "Warning from rspec -- make sure you're not attempting to call the actual 'retire' API"
        puts "within a block with description '#{self.class.description}'"
        minimal_response
      end
    end

    context "with no package.json file in root, and no sub-dirs" do
      let(:target) { 'no_findings_no_package_json' }
      subject(:task_findings) { task.run.analyze.findings }
      it { is_expected.to eq([]) }
    end

    context "with one package.json in the root dir" do
      let(:raw_report) { get_raw_report(target) }

      before do
        allow(task).to receive(:runsystem).with(*cli_args(target)).and_return(raw_report)
        task.run
        task.analyze
      end

      context "with no findings" do
        let(:target) { 'no_findings' }
        subject(:task_findings) { task.findings }
        it { is_expected.to eq([]) }
      end

      context "with one finding" do
        let(:finding) { task.findings.first }

        context "of low severity" do
          let(:target) { 'finding_1' }
          let(:package) { 'cli-0.11.3' }

          it "results in one finding" do
            expect(task.findings.size).to eq(1)
          end

          it "has severity 1" do
            expect(finding.severity).to eq(1)
          end

          it "has the correct 'finding' descriptors" do
            description = "Package #{package} has known security issues"
            detail = "https://nodesecurity.io/advisories/95"

            expect(finding.task).to eq("RetireJS")
            expect(finding.appname).to eq(target)
            expect(finding.description).to eq(description)
            expect(finding.detail).to eq(detail)
          end

          it "has the correct 'finding' source attribute" do
            source = {
              scanner: "RetireJS",
              file: "retirejs-test->#{package}",
              line: nil,
              code: nil
            }

            expect(finding.source).to eq(source)
          end

          it "has a self-consistent fingerprint" do
            fp = task.fingerprint("#{package}#{finding.source}#{finding.severity}")
            expect(finding.fingerprint).to eq(fp)
          end
        end

        context "of medium severity" do
          let(:target) { 'finding_2' }

          it "has severity 2" do
            expect(finding.severity).to eq(2)
          end
        end

        context "of high severity" do
          let(:target) { 'finding_3' }

          it "has severity 3" do
            expect(finding.severity).to eq(3)
          end
        end
      end

      context "with three findings without implicit dependencies" do
        let(:target) { 'findings_123' }
        let(:findings) { task.findings }

        it "results in 3 findings" do
          expect(findings.size).to eq(3)
        end

        it "has severities 1, 2, and 3" do
          expect(findings.map(&:severity).sort).to eq([1, 2, 3])
        end
      end

      context "with two findings one of which is implicit" do
        # The initial version of the task failed this one.
        #
        # The root package.json depends on 1.
        # Further, 1 depends on 2.
        #
        #  1
        #   \
        #    2

        let(:target) { 'findings_1-2' }
        let(:findings) { task.findings }

        it "results in 2 unique findings" do
          expect(findings.size).to eq(2)
        end

        it "has severities 1 and 2" do
          expect(findings.map(&:severity).sort).to eq([1, 2])
        end
      end

      context "with three findings with implicit dependencies on 1" do
        # The initial version of the task failed this one.
        #
        # The root package.json depends on 1, 2, and 3.
        # Further, 2 depends on 1, and 3 depends on 1.
        #
        #  1     2     3
        #       /     /
        #      1     1

        let(:target) { 'findings_123_2-1_3-1' }
        let(:findings) { task.findings }

        it "results in 3 unique findings" do
          expect(findings.size).to eq(3)
        end

        it "has severities 1, 2, and 3" do
          expect(findings.map(&:severity).sort).to eq([1, 2, 3])
        end
      end

      # context "with several findings in a non-trivial dependency structure" do
      #   #  1 = cli ( = findings[0] )
      #   #  2 = cookie-signature
      #   #  3 = pivottable
      #   #
      #   # In this example, the root package.json depends on 1, 2, and 3.
      #   # Further, 2 depends on 1, and 3 depends on 1 and 2.
      #   #
      #   #  1     2     3
      #   #       /     / \
      #   #      1     1   2
      #   #               /
      #   #              1
      #   #
      #   # Retire reports 7 results (one per node).
      #   # Glue should only report the 3 unique findings,
      #   # keeping track of all dependency paths for each.

      #   let(:target) { 'findings_123_2-1_3-12' }
      #   let(:raw_result) { JSON.parse(raw_report)["vulnerabilities"] }
      #   let(:findings) { task.findings }

      #   it "results in 3 findings" do
      #     expect(task.findings.size).to eq(3)
      #   end

      #   it "contains the upgrade paths for each finding" do
      #     expect(task.findings[0].source[:code]).to match("cli@0.11.3 -> cli@1.0.0")
      #     expect(task.findings[1].source[:code]).to match("cookie-signature@1.0.3 -> cookie-signature@1.0.4")
      #     expect(task.findings[2].source[:code]).to match("pivottable@1.4.0 -> pivottable@2.0.0")
      #   end

      #   it "has the correct number of vulnerable file paths per finding" do
      #     expect(task.findings[0].source[:file].split('<br>').size).to eq(4)
      #     expect(task.findings[1].source[:file].split('<br>').size).to eq(2)
      #     expect(task.findings[2].source[:file].split('<br>').size).to eq(1)
      #   end
      # end
    end

    # context "with three package.json files in different sub-dirs" do
    #   let(:target) { 'findings_1_2_3' }
    #   let(:args) { [1, 2, 3].map { |i| cli_args(target, "finding_#{i}") } }
    #   let(:raw_reports) { [1, 2, 3].map { |i| get_raw_report(target, "finding_#{i}") } }

    #   before do
    #     raw_reports.each_with_index do |raw_report, i|
    #       allow(task).to receive(:runsystem).with(*args[i]).and_return(raw_report)
    #     end
    #     task.run
    #     task.analyze
    #   end

    #   it "results in 3 findings" do
    #     expect(task.findings.size).to eq(3)
    #   end

    #   it "has one file path per finding" do
    #     task.findings.each do |finding|
    #       expect(finding.source[:file].split('<br>').size).to eq(1)
    #     end
    #   end
    # end

#     context "with malformed 'vulnerabilities'" do
#       # The .run method already guarantees that the raw reports were parsed,
#       # and that a 'vulnerabilities' key was found for each.
#       # (Each raw report's 'vulnerabilities' is an array of vulnerability hashes.)
#       # The .analyze method assumes that @results is an array of per-directory 'vulnerabilities' arrays.
#       # Each should be an array of vulnerability hashes with certain keys ('name', 'version', 'title', etc).

#       before { allow(Glue).to receive(:warn) } # stub to prevent printing to screen

#       context "in the root dir" do
#         let(:target) { 'malformed' }

#         before do
#           allow(task).to receive(:runsystem).with(*cli_args(target)).and_return(malformed_response)
#           task.run
#         end

#         context "equal to a non-array" do
#           # Would throw NoMethodError (calling .uniq on non-array):
#           let(:malformed_response) { JSON.generate({ vulnerabilities: true }) }

#           it "handles (does not raise) the NoMethodError" do
#             expect { task.analyze }.not_to raise_error
#           end

#           it "issues a notification matching 'Problem running Snyk'" do
#             expect(Glue).to receive(:notify).with(/Problem running Snyk/)
#             task.analyze rescue nil
#           end

#           it "issues a warning matching 'Error'" do
#             expect(Glue).to receive(:warn).with(/Error/)
#             task.analyze rescue nil
#           end
#         end

#         context "with a 'nil' vulnerability" do
#           # Would throw NoMethodError (trying to access a member of nil):
#           let(:malformed_response) { JSON.generate({ vulnerabilities: [nil] }) }

#           it "doesn't raise an error" do
#             expect { task.analyze }.not_to raise_error
#           end
#         end

#         context "with a vulnerability equal to an empty hash" do
#           # Would throw TypeError (trying to access eg 'id' of an empty hash):
#           let(:malformed_response) { JSON.generate({ vulnerabilities: [{}] }) }

#           it "doesn't raise an error" do
#             expect { task.analyze }.not_to raise_error
#           end
#         end
#       end

#       context "in a sub-dir, sibling to well-formed findings" do
#         let(:target) { 'malformed_nested'}
#         let(:sub_1_good) { 'finding_1' }
#         let(:sub_2_bad) { 'malformed' }
#         let(:sub_3_good) { 'zz_finding_1' }

#         let(:raw_report_1) { get_raw_report(target, sub_1_good) }
#         let(:malformed_response) { JSON.generate({ vulnerabilities: true }) }
#         let(:raw_report_3) { get_raw_report(target, sub_3_good) }

#         before do
#           allow(task).to receive(:runsystem).with(*cli_args(target, sub_1_good)).and_return(raw_report_1)
#           allow(task).to receive(:runsystem).with(*cli_args(target, sub_2_bad)).and_return(malformed_response)
#           allow(task).to receive(:runsystem).with(*cli_args(target, sub_3_good)).and_return(raw_report_3)
#           task.run
#         end

#         it "only issues one warning" do
#           expect(Glue).to receive(:warn).with(/Error/).once
#           task.analyze rescue nil
#         end

#         it "results in 2 findings (doesn't exit early)" do
#           task.analyze rescue nil
#           expect(task.findings.size).to eq(2)
#         end
#       end
#     end
  end
end
