#!/bin/bash

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
if command -v pyenv 1>/dev/null 2>&1; then
    eval "$(pyenv init -)"
fi

# Activate the specific Python version, 3.8.18
pyenv shell 3.8.18

pyenv exec otx2misp sample-misp.ini

# Optional: Deactivate the Python version
pyenv shell --unset