# decryptor_app.py

# Imports
import json # Example import for JSON storage
import tkinter as tk
import sqlite3 # Example import for SQLite storage
import re
# from google.generativeai import GenerativeModel # Example import for Gemini API

from ciphers import apply_cipher, test_all_cipher_combinations, parse_keywords, is_valid_keyword_for_cipher, generate_affine_combinations, generate_substitution_alphabet
from decryptor_ui import DecryptorUI

# --- Configuration ---
STORAGE_FILE = 'decryption_data.db' # Path to the SQLite DB

# --- Persistent Storage Functions ---

def load_data(storage_path: str) -> tuple[set, dict, list]:
    """
    Loads previously tested keyword-cipher pairs, problem data, and results from persistent storage.

    Args:
        storage_path: The path to the storage file (e.g., JSON or SQLite DB).

    Returns:
        A set of previously tested (keyword, cipher_method) tuples.
        A dictionary of problem data.
        A list of result data.
    """
    tested_pairs = set() # Change name to tested_pairs
    problems_data = {} # {tab_name: {'ciphertext': '...', 'keywords': [...]}}
    results_data_dict = {} # {tab_name: [{'keyword': '...', 'decrypted_text': '...', 'is_meaningful': True/False, 'cipher_method': '...'}]}

    try:
        conn = sqlite3.connect(storage_path)
        cursor = conn.cursor()

        # Create tables if they don't exist
        # Modify keywords table to store keyword and cipher_method
        cursor.execute("CREATE TABLE IF NOT EXISTS tested_pairs (keyword TEXT, cipher_method TEXT, PRIMARY KEY (keyword, cipher_method))")
        cursor.execute("CREATE TABLE IF NOT EXISTS problems (tab_name TEXT PRIMARY KEY, ciphertext TEXT, keywords TEXT)") # keywords stored as comma-separated string
        # Ensure results table has cipher_method column and tab_name
        cursor.execute("CREATE TABLE IF NOT EXISTS results (tab_name TEXT, keyword TEXT, decrypted_text TEXT, is_meaningful INTEGER, cipher_method TEXT)")

        # Load tested pairs
        cursor.execute("SELECT keyword, cipher_method FROM tested_pairs")
        tested_pairs = set(row for row in cursor.fetchall()) # Load tuples

        # Load problems first to get all tab names
        cursor.execute("SELECT tab_name, ciphertext, keywords FROM problems")
        for row in cursor.fetchall():
            tab_name, ciphertext, keywords_str = row
            problems_data[tab_name] = {
                'ciphertext': ciphertext,
                'keywords': [k.strip() for k in keywords_str.split(',') if k.strip()] if keywords_str else []
            }
            # Initialize results entry for this tab name
            results_data_dict[tab_name] = []

        # Load results and add to the initialized dictionary
        cursor.execute("SELECT tab_name, keyword, decrypted_text, is_meaningful, cipher_method FROM results")
        for row in cursor.fetchall():
            tab_name, keyword, decrypted_text, is_meaningful, cipher_method = row
            # Ensure the tab_name exists in problems_data before adding results
            if tab_name in problems_data:
                 results_data_dict[tab_name].append({
                    'keyword': keyword,
                    'decrypted_text': decrypted_text,
                    'is_meaningful': bool(is_meaningful),
                    'cipher_method': cipher_method
                })
            else:
                # Handle results for tabs that might no longer exist in problems_data
                # For now, we'll just print a warning. Could potentially keep them or discard.
                print(f"Warning: Found results for tab '{tab_name}' which does not exist in problems data.")
        print(f"Loaded {sum(len(results) for results in results_data_dict.values())} results from the database across {len(results_data_dict)} tabs.")
        conn.close()
    except Exception as e:
        print(f"Error loading data from storage: {e}")

    return tested_pairs, problems_data, results_data_dict # Return tested_pairs and results_data_dict

def save_single_result(tab_name: str, result: dict, storage_path: str):
    """
    Saves a single decryption result to the persistent storage.

    Args:
        result: A dictionary containing the result data.
        storage_path: The path to the storage file (SQLite DB).
    """
    try:
        conn = sqlite3.connect(storage_path)
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE IF NOT EXISTS results (tab_name TEXT, keyword TEXT, decrypted_text TEXT, is_meaningful INTEGER, cipher_method TEXT)")

        # Insert the single result
        cursor.execute("INSERT INTO results (tab_name, keyword, decrypted_text, is_meaningful, cipher_method) VALUES (?, ?, ?, ?, ?)",
                       (tab_name, result['keyword'], result['decrypted_text'], int(result['is_meaningful']), result['cipher_method']))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving single result to storage: {e}")

def clear_results_from_db(storage_path: str, tab_name: str = None):
    """
    Clears results from the results table in the database.
    If tab_name is provided, clears results only for that tab. Otherwise, clears all results.
    """
    try:
        conn = sqlite3.connect(storage_path)
        cursor = conn.cursor()

        if tab_name:
            cursor.execute("DELETE FROM results WHERE tab_name = ?", (tab_name,))
            print(f"Cleared results for tab '{tab_name}' from the database.")
        else:
            cursor.execute("DELETE FROM results")
            cursor.execute("DELETE FROM tested_pairs") # Also clear tested pairs if clearing all results
            print("Cleared all results and tested pairs from the database.")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error clearing data from database: {e}")

def save_data(tested_pairs: set, problems_data: dict, storage_path: str):
    """
    Saves the current set of tested keyword-cipher pairs and problem data to persistent storage.

    Args:
        tested_pairs: The set of (keyword, cipher_method) tuples to save.
        problems_data: The dictionary of problem data to save.
        storage_path: The path to the storage file (SQLite DB).
    """
    try:
        conn = sqlite3.connect(storage_path)
        cursor = conn.cursor()

        # Create tables if they don't exist
        cursor.execute("CREATE TABLE IF NOT EXISTS tested_pairs (keyword TEXT, cipher_method TEXT, PRIMARY KEY (keyword, cipher_method))")
        cursor.execute("CREATE TABLE IF NOT EXISTS results (tab_name TEXT, keyword TEXT, decrypted_text TEXT, is_meaningful INTEGER, cipher_method TEXT)")

        # Save tested pairs
        cursor.execute("DELETE FROM tested_pairs")
        for keyword, cipher_method in tested_pairs: # Iterate through tuples
            cursor.execute("INSERT OR IGNORE INTO tested_pairs (keyword, cipher_method) VALUES (?, ?)", (keyword, cipher_method))

        # Save problems (no change needed here)
        cursor.execute("DELETE FROM problems")
        for tab_name, data in problems_data.items():
            keywords_str = ','.join(data['keywords'])
            cursor.execute("INSERT OR REPLACE INTO problems (tab_name, ciphertext, keywords) VALUES (?, ?, ?)",
                           (tab_name, data['ciphertext'], keywords_str))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving data to storage: {e}")

# --- Gemini API Interaction ---

def evaluate_decryption_result(decrypted_text: str) -> bool:
    """
    Sends the decrypted text to the Google Gemini API for evaluation.

    Args:
        decrypted_text: The text to evaluate.

    Returns:
        True if the result is likely meaningful, False otherwise.
    """
    is_meaningful = False
    # TODO: Implement interaction with Google Gemini API
    # This will involve sending the decrypted_text to the API and parsing the response
    # print(f"Sending result to Gemini API for evaluation: '{decrypted_text[:50]}...'")
    # Example API call (requires setting up the API client and authentication)
    # model = GenerativeModel('gemini-pro')
    # response = model.generate_content(f"Is the following text meaningful English or gibberish? Respond with 'Meaningful' or 'Gibberish'.\n\n{decrypted_text}")
    # if response.text.strip().lower() == 'meaningful':
    #     is_meaningful = True
    # Placeholder logic
    import random
    is_meaningful = random.choice([True, False, False, False]) # Simulate some gibberish results
    print(f"Gemini API evaluation: {'Meaningful' if is_meaningful else 'Gibberish'}")
    return is_meaningful

# --- Main Application Logic ---

def run_decryption_process(ui_instance: DecryptorUI):
    """
    Orchestrates the decryption process triggered by the UI button.
    Gets UI inputs, runs tests, updates data, and saves.
    """
    global tested_pairs # Access global variables

    print("Decrypt button clicked. Running decryption process...")

    # Get inputs from the currently selected tab using the UI instance
    selected_tab_name = ui_instance.notebook.tab(ui_instance.notebook.select(), "text")
    ciphertext = ui_instance.get_ciphertext_from_ui()
    keywords_from_ui = ui_instance.get_keywords_from_ui()

    if not ciphertext or not keywords_from_ui:
        print("Please enter both cipher text and keywords.")
        ui_instance.display_result_in_ui("N/A", "Please enter both cipher text and keywords.", False, "N/A")
        return

    # Reload tested_pairs from the database to ensure we have the latest state after clearing
    tested_pairs, _, _ = load_data(STORAGE_FILE)
    print(f"Reloaded {len(tested_pairs)} tested pairs after getting UI inputs.")

    # Run comprehensive decryption tests for all cipher combinations
    run_comprehensive_decryption_tests(ciphertext, keywords_from_ui, tested_pairs, ui_instance, selected_tab_name)

    # Update and save all data
    current_problems_data = ui_instance.get_all_problem_data()

    # Save updated tested keywords and problems data. Results are saved individually via the UI instance.
    save_data(tested_pairs, current_problems_data, STORAGE_FILE)
    print(f"Saved {len(tested_pairs)} processed keyword-cipher pairs (including skipped) and {len(current_problems_data)} problems.")

    print("Decryption process finished.")

def run_comprehensive_decryption_tests(ciphertext: str, keywords_input: str, tested_pairs: set, ui_instance: DecryptorUI, tab_name: str):
    """
    Runs comprehensive decryption tests for ALL cipher combinations and displays results.

    Args:
        ciphertext: The text to decrypt.
        keywords_input: String of keywords (comma or newline separated).
        tested_pairs: A set of previously tested (keyword, cipher_method) tuples.
        ui_instance: The UI instance for displaying results.
    """
    print("Running comprehensive decryption tests for all cipher combinations...")
    
    # Parse keywords from input string
    keywords = parse_keywords(",".join(keywords_input))
    if not keywords:
        print("No valid keywords found.")
        return
    
    print(f"Testing {len(keywords)} keywords: {keywords}")
    
    # Define all available cipher methods
    cipher_methods = [
        'caesar', 'rot13', 'atbash', 'vigenere', 'beaufort',
        'simple_substitution', 'affine', 'reverse', 
        'columnar_transposition', 'rail_fence', 'playfair'
    ]
    
    total_tests = 0
    new_tests = 0
    
    # Test each cipher method
    for cipher_method in cipher_methods:
        print(f"\n--- Testing {cipher_method.upper()} cipher ---")
        
        # Handle ciphers that don't need keywords
        if cipher_method in ['reverse', 'rot13', 'atbash']:
            current_pair = ('', cipher_method)
            if current_pair not in tested_pairs:
                print(f"Testing {cipher_method} (no keyword required)...")
                result = apply_cipher(ciphertext, '', cipher_method)
                is_meaningful = False
                
                if not result.startswith("Error:"):
                    is_meaningful = evaluate_decryption_result(result)
                    # Save result if not error
                    result_to_save = {
                        'keyword': '',
                        'decrypted_text': result,
                        'is_meaningful': is_meaningful,
                        'cipher_method': cipher_method
                    }
                    save_single_result(tab_name, result_to_save, STORAGE_FILE)
                
                # Display in UI
                ui_instance.display_result_in_ui('', result, is_meaningful, cipher_method)
                tested_pairs.add(current_pair)
                new_tests += 1
            else:
                print(f"{cipher_method} already tested. Skipping.")
            total_tests += 1
            continue
        
        # Generate special combinations for affine cipher
        if cipher_method == 'affine':
            affine_combos = generate_affine_combinations(keywords)
            print(f"Generated {len(affine_combos)} affine combinations: {affine_combos}")
            
            for combo in affine_combos:
                current_pair = (combo, cipher_method)
                if current_pair not in tested_pairs:
                    print(f"Testing affine cipher with combination: {combo}")
                    result = apply_cipher(ciphertext, combo, cipher_method)
                    is_meaningful = False
                    
                    if not result.startswith("Error:"):
                        is_meaningful = evaluate_decryption_result(result)
                        result_to_save = {
                            'keyword': combo,
                            'decrypted_text': result,
                            'is_meaningful': is_meaningful,
                            'cipher_method': cipher_method
                        }
                        save_single_result(tab_name, result_to_save, STORAGE_FILE)
                    
                    ui_instance.display_result_in_ui(combo, result, is_meaningful, cipher_method)
                    tested_pairs.add(current_pair)
                    new_tests += 1
                else:
                    print(f"Affine combination {combo} already tested. Skipping.")
                total_tests += 1
            continue
        
        # Generate substitution alphabets
        if cipher_method == 'simple_substitution':
            alphabets = generate_substitution_alphabet(keywords)
            print(f"Found {len(alphabets)} valid substitution alphabets: {alphabets}")
            
            for alphabet in alphabets:
                current_pair = (alphabet, cipher_method)
                if current_pair not in tested_pairs:
                    print(f"Testing simple substitution with alphabet: {alphabet}")
                    result = apply_cipher(ciphertext, alphabet, cipher_method)
                    is_meaningful = False
                    
                    if not result.startswith("Error:"):
                        is_meaningful = evaluate_decryption_result(result)
                        result_to_save = {
                            'keyword': alphabet,
                            'decrypted_text': result,
                            'is_meaningful': is_meaningful,
                            'cipher_method': cipher_method
                        }
                        save_single_result(tab_name, result_to_save, STORAGE_FILE)
                    
                    ui_instance.display_result_in_ui(alphabet, result, is_meaningful, cipher_method)
                    tested_pairs.add(current_pair)
                    new_tests += 1
                else:
                    print(f"Substitution alphabet {alphabet} already tested. Skipping.")
                total_tests += 1
            continue
        
        # Test regular keywords for other ciphers
        for keyword in keywords:
            current_pair = (keyword, cipher_method)
            
            if current_pair in tested_pairs:
                print(f"Keyword-cipher pair ({keyword}, {cipher_method}) already tested. Skipping.")
                total_tests += 1
                continue
            
            # Validate keyword for this cipher
            if not is_valid_keyword_for_cipher(keyword, cipher_method):
                print(f"Keyword '{keyword}' is not valid for cipher '{cipher_method}'. Skipping.")
                tested_pairs.add(current_pair)  # Mark as tested to avoid retrying
                total_tests += 1
                continue
            
            # Run the test
            print(f"Testing {cipher_method} with keyword: '{keyword}'")
            result = apply_cipher(ciphertext, keyword, cipher_method)
            is_meaningful = False
            
            if not result.startswith("Error:"):
                is_meaningful = evaluate_decryption_result(result)
                # Save result if not error
                result_to_save = {
                    'keyword': keyword,
                    'decrypted_text': result,
                    'is_meaningful': is_meaningful,
                    'cipher_method': cipher_method
                }
                save_single_result(tab_name, result_to_save, STORAGE_FILE)
            
            # Display in UI
            ui_instance.display_result_in_ui(keyword, result, is_meaningful, cipher_method)
            tested_pairs.add(current_pair)
            new_tests += 1
            total_tests += 1
    
    print(f"\nComprehensive testing completed!")
    print(f"Total possible tests: {total_tests}")
    print(f"New tests run: {new_tests}")
    print(f"Tests skipped (already done): {total_tests - new_tests}")

def main():
    """
    Main function to run the decryptor application.
    """
    print("Starting Enhanced Decryptor App with Comprehensive Cipher Testing...")

    global tested_pairs, results_data_dict # Access global variables
    # Load previously saved data
    tested_pairs, problems_data, results_data_dict = load_data(STORAGE_FILE) # Load tested_pairs and results_data_dict
    print(f"Loaded {len(tested_pairs)} previously processed keyword-cipher pairs, {len(problems_data)} problems, and {sum(len(results) for results in results_data_dict.values())} results across {len(results_data_dict)} tabs.")

    # Setup UI with loaded data, passing the save_single_result function and a command to save problems
    root = tk.Tk()
    ui_instance = DecryptorUI(root, problems_data, results_data_dict, save_problems_command=None)

    def save_problems_callback():
        """Callback function to save current problems from the UI."""
        global tested_pairs
        current_problems_data = ui_instance.get_all_problem_data()
        save_data(tested_pairs, current_problems_data, STORAGE_FILE)
        print(f"Saved {len(current_problems_data)} problems from the UI.")

    def handle_clear_results():
        """Handles clearing results for the currently selected tab from both UI and database."""
        global tested_pairs
        selected_tab_name = ui_instance.notebook.tab(ui_instance.notebook.select(), "text")
        ui_instance.clear_results() # This clears the UI display and the in-memory results_data for the tab
        clear_results_from_db(STORAGE_FILE, selected_tab_name) # Clear results for the specific tab in the DB
        # Note: Clearing tested_pairs here would clear ALL tested pairs, which is not desired when clearing a single tab's results.
        # Tested pairs should only be cleared when clearing ALL results (handled in clear_results_from_db when tab_name is None).
        print(f"Cleared results for tab '{selected_tab_name}' from memory and database.")

    ui_instance.set_run_command(lambda: run_decryption_process(ui_instance))
    ui_instance.set_clear_command(handle_clear_results)
    ui_instance.save_problems_command = save_problems_callback

    # Start the Tkinter event loop
    root.mainloop()

    print("Enhanced Decryptor App finished.")

def save_current_problems(ui_instance: DecryptorUI):
    """
    Retrieves current problem data from the UI and saves it to the database.
    """
    global tested_pairs
    current_problems_data = ui_instance.get_all_problem_data()
    save_data(tested_pairs, current_problems_data, STORAGE_FILE)
    print(f"Saved {len(current_problems_data)} problems from the UI.")

if __name__ == "__main__":
    main()