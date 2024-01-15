#!/bin/bash

LOG_FILE="$HOME/otx2misp/cron_otx2misp.log"
log_message() {
    echo "$(date +"%Y-%m-%d %T"): $1" >> $LOG_FILE
}

log_message "Starting otx2misp cron job."

export PATH="$HOME/.pyenv/bin:$PATH"
export PYENV_ROOT="$HOME/.pyenv"

cd $HOME/otx2misp
# Activate the specific Python version, 3.8.18
pyenv local 3.8.18
{
	pyenv exec otx2misp $HOME/otx2misp/misp.ini
} &>> $LOG_FILE

# Check if otx2misp ran successfully
if [ $? -eq 0 ]; then
    log_message "otx2misp job completed successfully."
else
    log_message "Error: otx2misp job failed."
fi
