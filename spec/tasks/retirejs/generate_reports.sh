#!/bin/bash
# Runs 'retire' on the contents of the 'targets' dir,
# storing the output in 'report.json' within each target folder.
#
# Include a 'SKIP.txt' file next to 'package.json'
# if you don't want retire to run on that target.
#
# This uses sed to find-replace the absolute file paths
# with truncated relative versions.
# (Some vulnerabilities report an abs file path.
# Glue attempts to parse this to a relative path, using 'relative_path'.
# But this will not work correctly for the canned reports of
# the spec tests, since the abs file path in the canned report
# won't necessarily match the abs file path on the user's machine.
# To get around this for the spec tests, we just convert the
# reported abs file paths to relative file paths.)

run_retire_recurs ()
{
  if [ -f package.json ] && [ ! -f SKIP.txt ]; then
    # pwd
    retire -c --outputformat json --outputpath report.json
    sed -i -e "s;$ABS_DIR/;;g" report.json
  fi

  for SUBTARGET in *
  do
    if [ -d $SUBTARGET ] && [ $SUBTARGET != "node_modules" ]; then
      cd $SUBTARGET
      run_retire_recurs
      cd ..
    fi
  done
}

DIR=`dirname $0`
# cd "$DIR/targets/"
cd "$DIR/test_targets/"
# cd "$DIR/finding_1/"
# cd "$DIR/finding_f1/"
ABS_DIR="$(pwd)"

run_retire_recurs
