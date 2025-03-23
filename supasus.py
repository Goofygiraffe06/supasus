#!/usr/bin/env python3

import argparse
import requests
import json
import os
import sys
from urllib.parse import urljoin
from colorama import init, Fore, Style
from prettytable import PrettyTable

# Initialize colorama for cross-platform color support
init()

# ASCII Banner
BANNER = """
   _______  ______  ____ ________  _______
  / ___/ / / / __ \/ __ `/ ___/ / / / ___/
 (__  ) /_/ / /_/ / /_/ (__  ) /_/ (__  ) 
/____/\__,_/ .___/\__,_/____/\__,_/____/  
          /_/                             
"""

DISCLAIMER = "Author: @Goofygiraffe06 - Use responsibly and only on systems you have permission to scan."

class SupabaseScanner:
    def __init__(self, domain, api_key, auth_token=None, verbose=False, show_data=False, table=None, dump=False, insert=False, delete=False):
        self.base_url = f"https://{domain}/rest/v1/"
        self.headers = {
            "apikey": api_key,
            "Content-Type": "application/json",
        }
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"
        self.verbose = verbose
        self.show_data = show_data
        self.table = table  # Specific table to focus on
        self.dump = dump    # Dump data flag
        self.insert = insert  # Interactive insert flag
        self.delete = delete  # Interactive delete flag
        self.empty_count = 0  # Track [MEDIUM] tables
        self.data_count = 0   # Track [HIGH] tables
        self.domain = domain
        self.swagger_spec = None
        self.log_file = f"{self.domain}/scan.log"
        os.makedirs(self.domain, exist_ok=True)

    def log(self, message, severity="INFO"):
        """Log messages with colored severity tags, message uncolored, and write to file."""
        tag_color = {
            "INFO": f"{Fore.CYAN}[INFO]{Style.RESET_ALL}",
            "MEDIUM": f"{Fore.YELLOW}[MEDIUM]{Style.RESET_ALL}",
            "HIGH": f"{Fore.RED}[HIGH]{Style.RESET_ALL}",
            "ERROR": f"{Fore.RED + Style.BRIGHT}[ERROR]{Style.RESET_ALL}",
            "DEBUG": f"{Fore.GREEN}[DEBUG]{Style.RESET_ALL}"
        }.get(severity, f"{Fore.CYAN}[INFO]{Style.RESET_ALL}")
        output = f"{tag_color} {message}"
        print(output)
        with open(self.log_file, "a") as f:
            f.write(f"{output.replace(Style.RESET_ALL, '')}\n")
        if self.verbose and severity == "DEBUG":
            debug_output = f"{Fore.GREEN}[DEBUG]{Style.RESET_ALL} {message}"
            print(debug_output)
            with open(self.log_file, "a") as f:
                f.write(f"[DEBUG] {message}\n")

    def check_accessibility(self):
        """Check if the Supabase site is accessible."""
        self.log("Checking site accessibility")
        try:
            response = requests.get(f"https://{self.domain}", timeout=5)
            if response.status_code in [200, 301, 302, 404]:
                self.log("Site is accessible")
                return True
            else:
                self.log(f"Site returned unexpected HTTP {response.status_code}", "ERROR")
                return False
        except requests.exceptions.RequestException as e:
            self.log(f"Site inaccessible: {e}", "ERROR")
            return False

    def fetch_swagger(self):
        """Fetch Swagger spec from the root endpoint."""
        self.log("Fetching Swagger specification")
        try:
            response = requests.get(self.base_url, headers=self.headers)
            if response.status_code == 200:
                self.log("Swagger spec retrieved successfully")
                self.swagger_spec = response.json()
                return self.swagger_spec
            else:
                self.log(f"Failed to retrieve Swagger spec: HTTP {response.status_code}", "ERROR")
                return None
        except requests.exceptions.RequestException as e:
            self.log(f"Network error: {e}", "ERROR")
            return None

    def extract_tables(self, swagger_spec):
        """Extract table names from Swagger definitions."""
        if not swagger_spec or "definitions" not in swagger_spec:
            self.log("No table definitions found in Swagger spec", "ERROR")
            return []
        
        definitions = swagger_spec["definitions"]
        tables = [key for key in definitions.keys() if not key.startswith("openapi_")]
        self.log(f"Identified {len(tables)} tables: {', '.join(tables)}")
        return tables

    def enumerate_columns(self, table_name):
        """Enumerate columns for a specific table from Swagger spec in a table."""
        if table_name not in self.swagger_spec["definitions"]:
            self.log(f"Table '{table_name}' not found in Swagger definitions", "ERROR")
            return None
        
        self.log(f"Enumerating columns for table '{table_name}'")
        properties = self.swagger_spec["definitions"][table_name].get("properties", {})
        table = PrettyTable()
        table.field_names = ["Column", "Type", "Format", "Description"]
        table.align["Column"] = "l"
        table.align["Description"] = "l"
        columns = {}
        for col, meta in properties.items():
            col_type = meta.get("type", "N/A")
            col_format = meta.get("format", "N/A")
            col_desc = meta.get("description", "N/A")
            table.add_row([col, col_type, col_format, col_desc])
            columns[col] = {"type": col_type, "format": col_format}
        print(table)
        with open(self.log_file, "a") as f:
            f.write(f"[INFO] Enumerating columns for table '{table_name}'\n")
            f.write(str(table) + "\n")
        return columns

    def dump_table(self, table_name):
        """Dump all data from a specific table to a JSON file."""
        url = urljoin(self.base_url, table_name)
        dump_file = f"{self.domain}/{table_name}.json"
        try:
            response = requests.get(f"{url}?select=*", headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                if data:
                    with open(dump_file, "w") as f:
                        json.dump(data, f, indent=2)
                    self.log(f"Table '{table_name}' data dumped to {dump_file}")
                else:
                    self.log(f"Table '{table_name}' is empty, no data dumped")
            else:
                self.log(f"Failed to dump table '{table_name}': HTTP {response.status_code}", "ERROR")
        except Exception as e:
            self.log(f"Error dumping table '{table_name}': {e}", "ERROR")

    def test_table(self, table_name):
        """Test table accessibility and log findings."""
        url = urljoin(self.base_url, table_name)
        try:
            response = requests.get(f"{url}?select=*&limit=1", headers=self.headers)
            status = response.status_code
            if status == 200:
                response_data = response.text.strip()
                if response_data == "[]":
                    self.empty_count += 1
                    self.log(f"{table_name} - Accessible but empty (RLS or no data)", "MEDIUM")
                else:
                    self.data_count += 1
                    self.log(f"{table_name} - Accessible with data (potential exposure)", "HIGH")
                    if self.dump and not self.table:
                        self.dump_table(table_name)
                if self.show_data:
                    self.log(f"{table_name} - Sample: {response_data[:100]}...")
                if self.verbose:
                    self.log(f"{table_name} - Raw response: {response_data}", "DEBUG")
            elif status == 403:
                self.log(f"{table_name} - Restricted (RLS likely enforced)")
            elif status == 404:
                self.log(f"{table_name} - Not found or inaccessible")
            else:
                self.log(f"{table_name} - Unexpected HTTP {status}", "ERROR")
        except Exception as e:
            self.log(f"{table_name} - Error: {e}", "ERROR")

    def interactive_insert(self, table_name):
        """Interactively prompt for column values and insert a row."""
        columns = self.enumerate_columns(table_name)
        if not columns:
            return

        self.log(f"Interactive insert into table '{table_name}'")
        payload = {}
        for col, meta in columns.items():
            if col == "id" and meta["format"] == "uuid":
                continue  # Skip UUID id, assume auto-generated
            if col in ["created_at", "updated_at"] and meta["format"] == "timestamp with time zone":
                continue  # Skip timestamps, assume DB handles them
            value = input(f"Enter value for '{col}' ({meta['type']}): ").strip()
            if value:
                if meta["type"] == "integer":
                    payload[col] = int(value)
                elif meta["type"] == "number":
                    payload[col] = float(value)
                elif meta["type"] == "boolean":
                    payload[col] = value.lower() in ["true", "t", "1"]
                else:
                    payload[col] = value

        if not payload:
            self.log("No data provided, insert aborted", "ERROR")
            return

        url = urljoin(self.base_url, table_name)
        try:
            response = requests.post(url, headers=self.headers, json=payload)
            if response.status_code == 201:
                self.log(f"Successfully inserted row into '{table_name}'")
                self.log(f"Response: {response.text}", "DEBUG")
            else:
                self.log(f"Failed to insert into '{table_name}': HTTP {response.status_code} - {response.text}", "ERROR")
        except Exception as e:
            self.log(f"Error inserting into '{table_name}': {e}", "ERROR")

    def interactive_delete(self, table_name):
        """Fetch last 5 rows, display them, and delete selected row by id."""
        url = urljoin(self.base_url, f"{table_name}?select=*&order=created_at.desc&limit=5")
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code != 200:
                self.log(f"Failed to fetch rows from '{table_name}': HTTP {response.status_code}", "ERROR")
                return
            rows = response.json()
            if not rows:
                self.log(f"No rows found in '{table_name}'", "INFO")
                return

            self.log(f"Last 5 rows from '{table_name}':")
            table = PrettyTable()
            table.field_names = ["Index", "ID (UUID)", "Content"]
            for i, row in enumerate(rows):
                table.add_row([i, row.get("id", "N/A"), row.get("content", "N/A")[:50]])
            print(table)

            choice = input("Enter the Index of the row to delete (or 'q' to quit): ").strip()
            if choice.lower() == "q":
                self.log("Delete operation cancelled")
                return
            if not choice.isdigit() or int(choice) >= len(rows):
                self.log("Invalid index selected", "ERROR")
                return

            row_id = rows[int(choice)]["id"]
            delete_url = urljoin(self.base_url, f"{table_name}?id=eq.{row_id}")
            response = requests.delete(delete_url, headers=self.headers)
            if response.status_code == 204:
                self.log(f"Successfully deleted row with ID '{row_id}' from '{table_name}'")
            else:
                self.log(f"Failed to delete row from '{table_name}': HTTP {response.status_code} - {response.text}", "ERROR")
        except Exception as e:
            self.log(f"Error during delete operation on '{table_name}': {e}", "ERROR")

    def scan(self):
        """Run the full scan and display results."""
        print(BANNER)
        print(DISCLAIMER)
        with open(self.log_file, "a") as f:
            f.write(BANNER + "\n" + DISCLAIMER + "\n")
        self.log("Starting Supabase API scan")
        if not self.check_accessibility():
            self.log("Scan aborted due to site inaccessibility", "ERROR")
            sys.exit(1)
        
        swagger_spec = self.fetch_swagger()
        if not swagger_spec:
            self.log("Scan aborted due to Swagger retrieval failure", "ERROR")
            sys.exit(1)

        tables = self.extract_tables(swagger_spec)
        if not tables:
            self.log("No tables identified for testing", "ERROR")
            sys.exit(0)

        if self.insert or self.delete:
            if not self.table:
                self.log("--table is required for --insert or --delete", "ERROR")
                sys.exit(1)
            if self.table not in tables:
                self.log(f"Specified table '{self.table}' not found in schema", "ERROR")
                sys.exit(1)
            if self.insert:
                self.interactive_insert(self.table)
            elif self.delete:
                self.interactive_delete(self.table)
        elif self.table:
            if self.table not in tables:
                self.log(f"Specified table '{self.table}' not found in schema", "ERROR")
                sys.exit(1)
            self.log(f"Focusing on specified table: {self.table}")
            self.enumerate_columns(self.table)
            self.test_table(self.table)
            if self.dump:
                self.dump_table(self.table)
        else:
            self.log("Testing table accessibility")
            for table in tables:
                self.test_table(table)
            self.log(f"Scan summary: {self.data_count} tables with data [HIGH], {self.empty_count} tables empty [MEDIUM]")
        self.log("Scan completed")

def parse_args():
    """Parse command-line arguments with clear help text."""
    parser = argparse.ArgumentParser(
        description="Supabase API Scanner - Automated table exposure testing",
        epilog="Examples:\n  ./supasus.py -d <domain> -k <key> --table messages --insert\n  ./supasus.py -d <domain> -k <key> --table messages --delete\n  ./supasus.py -d <domain> -k <key> --table messages --dump",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Target Supabase domain (e.g., <project-ref>.supabase.co)")
    parser.add_argument("-k", "--key", required=True, help="Supabase API key (anon or service_role)")
    parser.add_argument("-t", "--token", help="AUTH token (JWT) for authenticated requests")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--data", action="store_true", help="Show sample data for accessible tables")
    parser.add_argument("--table", help="Focus on a specific table for enumeration, insert, or delete")
    parser.add_argument("--dump", action="store_true", help="Dump table data (specific table with --table, all tables otherwise)")
    parser.add_argument("--insert", action="store_true", help="Interactively insert into the specified table")
    parser.add_argument("--delete", action="store_true", help="Interactively delete from the specified table")
    return parser.parse_args()

def main():
    args = parse_args()
    scanner = SupabaseScanner(args.domain, args.key, args.token, args.verbose, args.data, args.table, args.dump, args.insert, args.delete)
    scanner.scan()

if __name__ == "__main__":
    main()
