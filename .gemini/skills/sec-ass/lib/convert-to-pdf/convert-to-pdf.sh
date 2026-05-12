#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <assessment-directory>"
  exit 1
fi

ASSESSMENT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_FILE="$ASSESSMENT_DIR/.session.json"
HEADER_FILE="$ASSESSMENT_DIR/ReportHeader.md"
REPORT_FILE="$ASSESSMENT_DIR/Report.md"
CONCLUSIONS_FILE="$ASSESSMENT_DIR/ReportConclusions.md"

# Validate required files
for f in "$SESSION_FILE" "$HEADER_FILE" "$REPORT_FILE" "$CONCLUSIONS_FILE"; do
  if [ ! -f "$f" ]; then
    echo "Error: $(basename "$f") not found in $ASSESSMENT_DIR"
    exit 1
  fi
done

# Read session context
ACCOUNT_ID=$(python3 -c "import json; print(json.load(open('$SESSION_FILE')).get('project_id', json.load(open('$SESSION_FILE')).get('account_id', 'Unknown')))")
CUSTOMER=$(python3 -c "import json; print(json.load(open('$SESSION_FILE'))['customer'])")
DATE=$(date +"%B %d, %Y")
LOGO_PATH="$SCRIPT_DIR/Logo_Hero.svg"

# Build cover page HTML from template
COVER_HTML=$(sed \
  -e "s|{{LOGO_PATH}}|$LOGO_PATH|g" \
  -e "s|{{ACCOUNT_ID}}|$ACCOUNT_ID|g" \
  -e "s|{{CUSTOMER}}|$CUSTOMER|g" \
  -e "s|{{DATE}}|$DATE|g" \
  -e "s|{{REPORT_DESCRIPTION}}|Critical and High severity findings with recommendations|g" \
  "$SCRIPT_DIR/cover.html")

# Convert header and report markdown to HTML fragments
HEADER_HTML=$(pandoc "$HEADER_FILE" --syntax-highlighting=none)
REPORT_HTML=$(pandoc "$REPORT_FILE" --syntax-highlighting=none)
CONCLUSIONS_HTML=$(pandoc "$CONCLUSIONS_FILE" --syntax-highlighting=none)

# Combine into final HTML
COMBINED="$ASSESSMENT_DIR/_combined.html"
cat > "$COMBINED" << EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="$SCRIPT_DIR/style.css">
</head>
<body>
$(echo "$COVER_HTML" | sed -n '/<div class="cover-page"/,/<\/div>/p')
<div class="report-header">
$HEADER_HTML
</div>
$REPORT_HTML
$CONCLUSIONS_HTML
</body>
</html>
EOF

# Convert to PDF
PDF="$ASSESSMENT_DIR/Report.pdf"
weasyprint "$COMBINED" "$PDF"

# Clean up
rm "$COMBINED"

echo "PDF created: $PDF"
