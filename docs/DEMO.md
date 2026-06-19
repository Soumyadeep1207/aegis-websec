# Demo Script

1. Start the application.

   ```powershell
   python -m app
   ```

2. Open `http://127.0.0.1:5000`.

3. Choose a scan profile:

   - Quick passive for a fast non-invasive check
   - Standard for the normal demo
   - Deep crawl for a stronger advanced demo
   - Competition for the final IIT-level showcase

4. Run a scan against an authorized lab target, for example `http://testphp.vulnweb.com`.

5. Open the scan details page.

6. Show:

   - Severity counters
   - Risk score
   - A-F security grade
   - Assessment coverage matrix
   - Crawl coverage table
   - Findings grouped with CVSS scores
   - Evidence and remediation text
   - JSON export
   - PDF report download

7. Explain that scanner modules are independent Python classes under `app/scanner/modules.py`, so more OWASP checks can be added cleanly.
