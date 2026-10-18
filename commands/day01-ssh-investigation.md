Day 1 — SSH investigation

# Identify the current user and system
whoami
hostname
date -Is

# Review recent login sessions
who
w
last -ai

# Review failed login records (may require root privileges)
sudo lastb -ai

# Review SSH service status
sudo systemctl status ssh --no-pager

# Review recent SSH service logs
sudo journalctl -u ssh --since "24 hours ago" --no-pager

# Search authentication logs for SSH-related events
sudo grep -Ei \
'Failed password|Accepted password|Accepted publickey|Invalid user|authentication failure' \
/var/log/auth.log

# Check whether a service is listening on TCP port 22
sudo ss -lntp | grep ':22'
