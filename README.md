## Supaslap

**Supaslap** is a Python-based command-line tool designed to identify and exploit vulnerabilities in poorly configured Supabase clients, enabling unauthorized access or control. it targets weaknesses in Supabase REST APIs, such as exposed tables and keys, to demonstrate the risks of insecure setups.

### Core Functionality

Supaslap operates by probing Supabase instances and exploiting their weaknesses with a streamlined set of features:

- **Vulnerability Scanning**: Checks the Supabase API for a list of tables and tests each one for accessibility, flagging those that return data or allow access without proper restrictions.
- **Data Extraction**: Pulls all data from unprotected tables and saves it to JSON files, showing a preview in a readable table format.
- **Data Manipulation**: Offers options to add new rows or delete existing ones interactively, taking advantage of writable endpoints.
- **Key Harvesting**: Looks for API keys in responses or public code, collecting them for potential further use.
- **Logging**: Keeps a record of all actions in a log file, with color-coded output for easy tracking.

### Key Features
- **Vulnerability Detection**: Finds tables and keys exposed due to weak security settings.
- **Data Retrieval**: Extracts and displays table contents from vulnerable endpoints.
- **Data Manipulation**: Allows insertion and deletion to disrupt or control clients.
- **Detailed Logging**: Tracks actions for analysis.

### License
Supaslap is distributed under the **GNU General Public License v3.0 (GPL-3.0)**, ensuring its source code is freely available and any derivative works remain open under the same license.

### Ethical Disclaimer
Supaslap is intended for educational purposes, security research, or authorized testing only. **Using it against systems without explicit permission is illegal and unethical.** The author is not responsible for any misuse or resulting harm.
