#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo
echo "========================================"
echo "   IOC Log Analyzer with VirusTotal"
echo "========================================"
echo

# Pick a Python interpreter
if command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "[ERROR] Python not found. Install Python 3 first." >&2
    exit 1
fi
echo "[OK] Python found: $($PY --version 2>&1)"
echo

# Sanity-check required files
[[ -f analyzer.py    ]] || { echo "[ERROR] analyzer.py not found"   >&2; exit 1; }
[[ -f ioc_list.json  ]] || { echo "[ERROR] ioc_list.json not found" >&2; exit 1; }
[[ -f vt_config.json ]] || echo "[WARN] vt_config.json not found — VT modes will fail."

echo "[OK] All files found"
echo

while true; do
    cat <<EOF
========================================
           ANALYSIS MODES
========================================

  1) Log analysis only (fast)
  2) Log analysis + VirusTotal check
  3) VirusTotal IOC check only
  4) Exit

========================================
EOF
    read -rp "Enter number (1-4): " choice
    case "$choice" in
        1)
            echo
            echo "=== Basic log analysis ==="
            "$PY" analyzer.py --log apache.log --ioc ioc_list.json --output alerts.csv
            break
            ;;
        2)
            echo
            echo "=== Full analysis with VirusTotal ==="
            "$PY" analyzer.py --log apache.log --ioc ioc_list.json \
                --vt-config vt_config.json --vt-check --output alerts.csv
            break
            ;;
        3)
            echo
            echo "=== VirusTotal IOC check only ==="
            "$PY" analyzer.py --ioc ioc_list.json --vt-config vt_config.json --vt-only
            break
            ;;
        4)
            echo "Exit..."
            exit 0
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
done

echo
echo "========================================"
echo "Analysis completed!"
echo
echo "Results saved to:"
echo "  - alerts.csv             (IOCs found in logs)"
echo "  - virustotal_results.json (VirusTotal results)"
echo "  - .vt_cache.json         (persistent VT cache)"
echo
echo "All files are in the src/ folder"
echo "========================================"
