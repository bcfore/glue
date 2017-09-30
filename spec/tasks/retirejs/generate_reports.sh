#!/bin/bash
# Runs 'retire' on the contents of the 'targets' dir,
# storing the output in 'report.json' within each target folder.
#
# Include a 'SKIP.txt' file next to 'package.json'
# if you don't want snyk to run on that target.

run_retire_recurs ()
{
  if [ -f package.json ] && [ ! -f SKIP.txt ]; then
    # pwd
    retire -c --outputformat json --outputpath report.json
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
cd "$DIR/targets/"
run_retire_recurs
