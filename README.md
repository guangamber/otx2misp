# otx2misp
V1.0: Import new OTX pulse to MISP

# setup
pip3 install git+https://github.com/guangamber/otx2misp.git

# run
otx2misp /path/misp.ini

# issues
1. if you are installing the package on a local misp server, which may have an older version, use the following to force upgrade
pip3 install --no-cache-dir --upgrade pymisp
2. if you have python version compatibility issues, consider pyenv, sample commands:
    2.1 PYTHON_CONFIGURE_OPTS="--enable-loadable-sqlite-extensions --enable-optimizations" 
    2.2 $HOME/.pyenv/bin/pyenv install 3.8
    2.3 $HOME/.pyenv/bin/pyenv exec pip install urllib3==1.26.6
    2.4 $HOME/.pyenv/bin/pyenv exec otx2misp misp.ini