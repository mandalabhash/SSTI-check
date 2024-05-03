# SSTI-check

## Description
SSTI-check is a graphical user interface (GUI) tool designed for educational purposes. It allows users to scan target URLs for Server-Side Template Injection (SSTI) vulnerabilities. The tool provides a user-friendly interface for inputting URLs, selecting payloads, executing scans, and viewing results.

## Outputs
The tool displays the scan results in three main sections:

1. **Output Text Area**: Provides real-time updates on the scanning process, including notifications, errors, and execution status.
2. **Passed URLs**: A scrolled text area showing the URLs of the scanned targets where SSTI vulnerabilities were detected.
3. **Results Treeview**: A tabular view presenting the payload, result (Pass/Fail), and vulnerable URL (if applicable) for each payload tested.

## Running the Code
To run the SSTI-check tool, follow these steps:

1. Clone the repository to your local machine:
   ```
   git clone https://github.com/mandalabhash/SSTI-check.git
   ```

2. Navigate to the project directory:
   ```
   cd SSTI-check
   ```

3. Install the required modules listed in the `requirements.txt` file:
   ```
   pip install -r requirements.txt
   ```

4. Run the Python script:
   ```
   python3 main.py
   ```

5. Once the GUI window opens, enter the target URL in the designated text field.

6. Click on the "Go" button to start the scanning process.

Please note that SSTI-check is intended for educational purposes only. Use it responsibly and ensure you have proper authorization before scanning any URLs.
```
