# My Dropbox Service #

## Installation ##

I personally keep this directory in my Dropbox folder in a location such as

	$HOME/Dropbox/bin/python_modules

In `.bash_profile` I add the following to allow me to import this within a python shell

	export PYTHONPATH=$PYTHONPATH:"$HOME/Dropbox/bin/python_modules"

Be sure to update `APP_KEY` and `APP_SECRET` within the `MyDropbox` class.

## Linking Your Dropbox Account ##

Open a python shell by running `python` in Terminal and run the following command and follow through the steps

	from mydropbox import MyDropbox  
	
	MyDropbox.link_account()

## Using Within a Script ##

You'll need to append your `PYTHONPATH` in order to use the script

	#!/usr/bin/python
	import sys
	sys.path.append('/Users/rjames/Dropbox/Sync/bin/python_modules')

	from mydropbox import MyDropbox

