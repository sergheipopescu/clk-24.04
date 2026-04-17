#!/bin/bash
set -euo pipefail

echo "=============================================="
echo " SundayMass Maintenance Setup Script"
echo "=============================================="
echo ""

# --- Ask for email address ---
read -r -p "Enter the email address to receive maintenance reports: " ADMIN_EMAIL

# Validate
if [[ -z "$ADMIN_EMAIL" ]]; then
    echo "Error: Email address cannot be empty."
    exit 1
fi
if ! [[ "$ADMIN_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
    echo "Error: Invalid email format."
    exit 1
fi

echo ""
echo "Using email address: $ADMIN_EMAIL"
echo "----------------------------------------------"
echo ""

# --- Logging directory ---
echo "=== Creating log directory with proper permissions ==="
sudo mkdir -p /var/log/sundaymass
sudo touch /var/log/sundaymass/clk-sundaymass.log
sudo chown root:adm /var/log/sundaymass /var/log/sundaymass/clk-sundaymass.log
sudo chmod 750 /var/log/sundaymass
sudo chmod 640 /var/log/sundaymass/clk-sundaymass.log

# --- Install HTML template ---
echo "=== Installing HTML report template ==="

sudo tee /usr/local/share/clk-massreport-tpl.html > /dev/null << 'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<title>Clickwork SundayMass Report</title>
</head>
<body style="margin:0; padding:0; background:#f4f6f8; font-family:Arial, sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8; padding:20px 0;">
  <tr>
    <td align="center">

      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 4px 12px rgba(0,0,0,0.08);">

        <tr>
          <td style="background:#3949ab; padding:20px; color:white; text-align:center; font-size:24px; font-weight:bold;">
            Clickwork SundayMass Report
          </td>
        </tr>

        <tr>
          <td style="padding:20px;">
            <h2 style="margin:0 0 15px 0; font-size:20px; color:#333;">Summary</h2>

            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:10px; background:#e8f5e9; border-radius:6px; font-size:16px; color:#2e7d32;">
                  ✓ Updates installed successfully
                </td>
              </tr>
              <tr>
                <td style="padding:10px; background:#e8f5e9; border-radius:6px; margin-top:10px; font-size:16px; color:#2e7d32;">
                  ✓ Cleanup completed (autoremove, autoclean, clean)
                </td>
              </tr>
              <tr>
                <td style="padding:10px; background:#fff3e0; border-radius:6px; margin-top:10px; font-size:16px; color:#ef6c00;">
                  ⏳ System reboot scheduled in 1 minute
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <tr>
          <td style="padding:20px;">
            <h2 style="margin:0 0 10px 0; font-size:20px; color:#333;">Details</h2>

            <div style="background:#e3f2fd; padding:15px; border-radius:6px; font-size:14px; color:#0d47a1;">
              <strong>Date:</strong> {{DATE}}<br>
              <strong>Host:</strong> {{HOSTNAME}}<br>
              <strong>Kernel:</strong> {{KERNEL}}
            </div>
          </td>
        </tr>

        <tr>
          <td style="padding:20px;">
            <h2 style="margin:0 0 10px 0; font-size:20px; color:#333;">Full Log Output</h2>

            <!-- LOG CONTENTS HERE -->
            {{LOG_CONTENTS}}

          </td>
        </tr>

        <tr>
          <td style="background:#f4f6f8; padding:15px; text-align:center; font-size:12px; color:#777;">
            Clickwork SundayMass • Automated Weekly Maintenance System
          </td>
        </tr>

      </table>

    </td>
  </tr>
</table>

</body>
</html>
EOF

# --- Install report/email helper script ---
echo "=== Installing report helper script ==="

sudo tee /usr/local/bin/clk-massreport.sh > /dev/null << EOF
#!/bin/bash
set -euo pipefail

ADMIN_EMAIL="${ADMIN_EMAIL}"
TEMPLATE="/usr/local/share/clk-massreport-tpl.html"
LOG="/var/log/sundaymass/clk-sundaymass.log"
REPORT=\$(mktemp /tmp/sundaymass-report-XXXX.html)

SYS_HOSTNAME=\$(hostname)
DATE=\$(date)
KERNEL=\$(uname -r)

# Write top half of template (before LOG_CONTENTS), substituting placeholders
awk '/{{LOG_CONTENTS}}/ { exit } { print }' "\$TEMPLATE" \
    | sed -e "s/{{DATE}}/\$DATE/" \
          -e "s/{{HOSTNAME}}/\$SYS_HOSTNAME/" \
          -e "s/{{KERNEL}}/\$KERNEL/" \
    > "\$REPORT"

# Insert PRE block
echo '<pre style="background:#f1f1f1; padding:15px; border-radius:6px; font-size:12px; color:#333; white-space:pre-wrap; word-wrap:break-word;">' >> "\$REPORT"

# Append escaped log contents
sed \
  -e 's/&/\&amp;/g' \
  -e 's/</\&lt;/g' \
  -e 's/>/\&gt;/g' \
  "\$LOG" >> "\$REPORT"

# Close PRE block
echo '</pre>' >> "\$REPORT"

# Append bottom half of template
awk 'found { print } /{{LOG_CONTENTS}}/ { found=1 }' "\$TEMPLATE" >> "\$REPORT"

# Send HTML email via Postfix
sendmail -t << MAIL
To: \$ADMIN_EMAIL
From: SundayMass@\$SYS_HOSTNAME
Subject: Clickwork SundayMass Report
Content-Type: text/html
Content-Transfer-Encoding: 8bit

\$(cat "\$REPORT")
MAIL

rm -f "\$REPORT"
EOF

sudo chmod 750 /usr/local/bin/clk-massreport.sh

# --- Create systemd service ---
echo "=== Creating systemd service ==="

sudo tee /etc/systemd/system/clk-sundaymass.service > /dev/null << 'EOF'
[Unit]
Description=SundayMass system update, cleanup, HTML report, and reboot

[Service]
Type=oneshot

StandardOutput=append:/var/log/sundaymass/clk-sundaymass.log
StandardError=append:/var/log/sundaymass/clk-sundaymass.log

ExecStart=/usr/bin/apt update
ExecStart=/usr/bin/apt upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
ExecStart=/usr/bin/apt autoremove -y
ExecStart=/usr/bin/apt autoclean
ExecStart=/usr/bin/apt clean

ExecStartPost=/usr/local/bin/clk-massreport.sh
ExecStartPost=/sbin/shutdown -r +1 "SundayMass maintenance complete. System will reboot in 1 minute."
EOF

# --- Timer ---
echo "=== Creating systemd timer ==="

sudo tee /etc/systemd/system/clk-sundaymass.timer > /dev/null << 'EOF'
[Unit]
Description=Run SundayMass maintenance every Sunday at 10 AM

[Timer]
OnCalendar=Sun 10:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# --- Logrotate ---
echo "=== Creating logrotate config ==="

sudo tee /etc/logrotate.d/clk-sundaymass > /dev/null << 'EOF'
/var/log/sundaymass/clk-sundaymass.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    su root adm
}
EOF

# Reload and enable timer
echo "=== Reloading and enabling timer ==="
sudo systemctl daemon-reload
sudo systemctl enable --now clk-sundaymass.timer

echo ""
echo "=============================================="
echo " SETUP COMPLETE!"
echo "=============================================="
echo "SundayMass weekly maintenance is active."
echo "HTML reports sent to: $ADMIN_EMAIL"
echo "Reboot occurs 1 minute after maintenance finishes."
echo ""
systemctl list-timers | grep clk-sundaymass || true
echo ""