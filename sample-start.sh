#!/bin/bash

# Load the user's profile - might be optional if full paths are specified correctly
source $HOME/.bash_profile

# Full path to pyenv executable if it does not work
PYENV="$HOME/.pyenv/bin/pyenv"

# Initialize pyenv
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$($PYENV init -)"

# Activate the specific Python version
$PYENV shell 3.8.18

$PYENV exec otx2misp misp.ini

# Deactivate the Python version
$PYENV shell --unset
