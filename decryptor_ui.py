import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk

class DecryptorUI:
    def __init__(self, root, problems_data, results_data_dict, save_problems_command=None):
        self.root = root
        self.problems_data = problems_data
        self.results_data = results_data_dict # This will now be a dictionary {tab_name: [results]}
        self.run_command = None
        self.clear_command = None
        self.save_problems_command = save_problems_command

        self.problem_inputs = {} # {tab_name: {'ciphertext': widget, 'keywords': widget}}

        self.setup_ui()

    def setup_ui(self):
        """
        Sets up the basic user interface using Tkinter.
        """
        self.root.title("Deciphenator 3000")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(pady=10, padx=10, fill="both", expand="yes")

        # Load problems and populate tabs
        if self.problems_data:
            for problem_name, data in self.problems_data.items():
                self.add_problem_tab(self.notebook, problem_name, data['ciphertext'], data['keywords'])
        else:
            # If no problems loaded, add a default tab
            self.add_problem_tab(self.notebook)


        # Add a button to add new problem tabs (optional, but useful)
        add_problem_button = tk.Button(self.root, text="Add New Problem Tab", command=lambda: self.add_problem_tab(self.notebook))
        add_problem_button.pack(pady=5)

        # Results Display (Placeholder for now) - This will be outside the notebook
        results_frame = tk.LabelFrame(self.root, text="Results")
        results_frame.pack(pady=10, padx=10, fill="both", expand="yes")

        # Use Treeview for tabular results display
        self.results_tree = ttk.Treeview(results_frame, columns=("Keyword", "Cipher", "Status", "Result"), show="headings")
        self.results_tree.heading("Keyword", text="Keyword")
        self.results_tree.heading("Cipher", text="Cipher")
        self.results_tree.heading("Status", text="Status")
        self.results_tree.heading("Result", text="Result")

        # Optional: Configure column widths
        self.results_tree.column("Keyword", width=100)
        self.results_tree.column("Cipher", width=100)
        self.results_tree.column("Status", width=80)
        self.results_tree.column("Result", width=300)

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.pack(pady=5, padx=5, fill="both", expand="yes", side=tk.LEFT)

        # Results will be populated based on the selected tab
        # Initial population will happen after setup is complete

        # Add a button to trigger decryption (will implement command later)
        # This button will now process the inputs from the currently selected problem tab
        decrypt_button = tk.Button(self.root, text="Run Decryption Tests", command=lambda: self.run_command())
        decrypt_button.pack(pady=10)

        # Add a button to clear results
        clear_button = tk.Button(self.root, text="Clear Results", command=lambda: self.clear_command())
        clear_button.pack(pady=5)

        # Bind the double-click event to the show_full_result method
        self.results_tree.bind("<Double-1>", self.show_full_result)

        # Bind tab change event to update results display
        self.notebook.bind("<<NotebookTabChanged>>", self.update_results_display)

        # Initial display of results for the first tab
        self.update_results_display()

        print("UI setup complete with problem tabs.")

    def add_problem_tab(self, notebook, tab_name=None, ciphertext="", keywords=""):
        """Adds a new problem tab to the notebook."""
        if tab_name is None:
            tab_name = f"Problem {len(notebook.tabs()) + 1}"

        frame = ttk.Frame(notebook, padding="10")
        notebook.add(frame, text=tab_name)

        # Add widgets for renaming the tab
        rename_frame = tk.Frame(frame)
        rename_frame.pack(pady=5, fill="x")

        rename_label = tk.Label(rename_frame, text="Tab Name:")
        rename_label.pack(side=tk.LEFT, padx=(0, 5))

        rename_entry = tk.Entry(rename_frame)
        rename_entry.insert(0, tab_name) # Set initial text to the current tab name
        rename_entry.pack(side=tk.LEFT, expand=True, fill="x", padx=(0, 5))

        # Use a lambda to pass the current tab name and entry widget to the rename function
        rename_button = tk.Button(rename_frame, text="Rename", command=lambda name_entry=rename_entry, current_name=tab_name: self.rename_tab(notebook, current_name, name_entry))
        rename_button.pack(side=tk.LEFT)


        # Cipher Text Input for the new tab
        cipher_frame = tk.LabelFrame(frame, text="Cipher Text")
        cipher_frame.pack(pady=5, fill="both", expand="yes")
        ciphertext_text_widget = scrolledtext.ScrolledText(cipher_frame, wrap=tk.WORD, width=60, height=10)
        ciphertext_text_widget.insert(tk.END, ciphertext)
        ciphertext_text_widget.pack(pady=5, padx=5, fill="both", expand="yes")

        # Keywords Input for the new tab
        keywords_frame = tk.LabelFrame(frame, text="Keywords (comma or newline separated)")
        keywords_frame.pack(pady=5, fill="both", expand="yes")
        keywords_text_widget = scrolledtext.ScrolledText(keywords_frame, wrap=tk.WORD, width=60, height=5)
        keywords_text_widget.insert(tk.END, ", ".join(keywords) if isinstance(keywords, list) else keywords)
        keywords_text_widget.pack(pady=5, padx=5, fill="both", expand="yes")

        # Store the text widgets for the new problem tab
        self.problem_inputs[tab_name] = {
            'ciphertext': ciphertext_text_widget,
            'keywords': keywords_text_widget
        }

        # Initialize an empty list for results for the new tab
        if tab_name not in self.results_data:
            self.results_data[tab_name] = []

        # Select the newly added tab
        notebook.select(frame)

        # Save problems after adding a new tab
        if self.save_problems_command:
            self.save_problems_command()

    def rename_tab(self, notebook, old_name: str, name_entry_widget: tk.Entry):
        """
        Renames a problem tab in the notebook and updates the problem_inputs dictionary.
        """
        new_name = name_entry_widget.get().strip()
        if not new_name or new_name == old_name:
            print("Invalid or same tab name provided.")
            return

        # Find the tab ID by iterating through the notebook tabs
        tab_id_to_rename = None
        for tab_id in notebook.tabs():
            if notebook.tab(tab_id, "text") == old_name:
                tab_id_to_rename = tab_id
                break

        if tab_id_to_rename is not None:
            notebook.tab(tab_id_to_rename, text=new_name)
            # Update the key in the problem_inputs dictionary
            if old_name in self.problem_inputs:
                self.problem_inputs[new_name] = self.problem_inputs.pop(old_name)
                # Also update the key in the results_data dictionary
                if old_name in self.results_data:
                    self.results_data[new_name] = self.results_data.pop(old_name)
                print(f"Tab '{old_name}' renamed to '{new_name}'.")
                # Call the save command if provided
                if self.save_problems_command:
                    self.save_problems_command()
            else:
                print(f"Error: Could not find problem input entry for tab '{old_name}'.")
        else:
            print(f"Error: Could not find tab with name '{old_name}'.")


    def get_ciphertext_from_ui(self) -> str:
        """
        Retrieves the cipher text entered by the user in the UI.
        """
        # Get text from the scrolled text widget of the currently selected tab
        # Get text from the scrolled text widget of the currently selected problem tab
        selected_tab_id = self.notebook.select()
        selected_tab_name = self.notebook.tab(selected_tab_id, "text")
        ciphertext = self.problem_inputs[selected_tab_name]['ciphertext'].get("1.0", tk.END).strip()
        print(f"Getting ciphertext from UI for '{selected_tab_name}' tab: '{ciphertext[:50]}...'")
        return ciphertext

    def get_keywords_from_ui(self) -> list[str]:
        """
        Retrieves the list of keywords/numbers entered by the user in the UI.
        """
        # Get text from the scrolled text widget of the currently selected tab
        # Get text from the scrolled text widget of the currently selected problem tab
        selected_tab_id = self.notebook.select()
        selected_tab_name = self.notebook.tab(selected_tab_id, "text")
        keywords_string = self.problem_inputs[selected_tab_name]['keywords'].get("1.0", tk.END).strip()
        keywords = [k.strip() for k in keywords_string.replace(',', '\n').split('\n') if k.strip()]
        print(f"Getting keywords from UI for '{selected_tab_name}' tab: {keywords}")
        return keywords

    def display_result_in_ui(self, original_keyword: str, decrypted_text: str, is_meaningful: bool, cipher_method: str):
        """
        Displays a decryption result in the UI.
        """
        status = "Meaningful" if is_meaningful else "Gibberish"
        selected_tab_id = self.notebook.select()
        selected_tab_name = self.notebook.tab(selected_tab_id, "text")

        # Add the result to the results_data for the current tab
        if selected_tab_name not in self.results_data:
            self.results_data[selected_tab_name] = []

        result_to_add = {
            'keyword': original_keyword,
            'decrypted_text': decrypted_text,
            'is_meaningful': is_meaningful,
            'cipher_method': cipher_method
        }
        self.results_data[selected_tab_name].append(result_to_add)

        # Update the displayed results in the Treeview
        self.update_results_display()

        print(f"Displaying result for tab '{selected_tab_name}': Keyword: '{original_keyword}', Cipher: '{cipher_method}', Status: '{status}', Result: '{decrypted_text[:100]}...'")

    def set_run_command(self, command):
        self.run_command = command

    def set_clear_command(self, command):
        self.clear_command = command

    def clear_results(self):
        """
        Clears results for the currently selected tab from the UI and the internal data structure.
        """
        selected_tab_id = self.notebook.select()
        selected_tab_name = self.notebook.tab(selected_tab_id, "text")

        if selected_tab_name in self.results_data:
            self.results_data[selected_tab_name] = []
            print(f"Cleared results for tab '{selected_tab_name}' from internal data.")

        # Clear the Treeview display
        if self.results_tree:
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            print("Results treeview display cleared.")

        # The clear command in decryptor_app.py will handle clearing from the database

    def update_results_display(self, event=None):
        """
        Clears the current results display and populates it with results for the selected tab.
        """
        # Clear current display
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        selected_tab_id = self.notebook.select()
        selected_tab_name = self.notebook.tab(selected_tab_id, "text")

        if selected_tab_name in self.results_data:
            for result in self.results_data[selected_tab_name]:
                status = "Meaningful" if result['is_meaningful'] else "Gibberish"
                item_id = self.results_tree.insert("", tk.END, values=(result['keyword'], result['cipher_method'], status, result['decrypted_text'][:100] + "..."))
                self.results_tree.item(item_id, tags=('full_data', result['keyword'], result['cipher_method'], status, result['decrypted_text']))
            print(f"Updated results display for tab '{selected_tab_name}' with {len(self.results_data[selected_tab_name])} results.")
        else:
            print(f"No results found for tab '{selected_tab_name}'.")


    def show_full_result(self, event):
        """
        Handles the double-click event on the results treeview to show the full result in a new window.
        Retrieves data from the results_data dictionary based on the selected tab and clicked item.
        """
        selected_item = self.results_tree.focus() # Get the currently selected item
        if not selected_item:
            return # No item selected

        # Retrieve the full data from the item's tags
        # The tags are stored as ('full_data', keyword, cipher_method, status, decrypted_text)
        tags = self.results_tree.item(selected_item, 'tags')
        if 'full_data' in tags:
            # Find the index of 'full_data' and extract the subsequent elements
            try:
                full_data_index = tags.index('full_data')
                # Ensure there are enough elements after 'full_data'
                if len(tags) > full_data_index + 4:
                    keyword = tags[full_data_index + 1]
                    cipher_method = tags[full_data_index + 2]
                    status = tags[full_data_index + 3]
                    decrypted_text = tags[full_data_index + 4]

                    # Create a new top-level window for the full result
                    detail_window = tk.Toplevel(self.root)
                    detail_window.title(f"Full Result: {keyword} ({cipher_method})")

                    # Add a scrolled text widget to display the full decrypted text
                    full_text_widget = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD, width=80, height=20)
                    full_text_widget.insert(tk.END, f"Keyword: {keyword}\n")
                    full_text_widget.insert(tk.END, f"Cipher Method: {cipher_method}\n")
                    full_text_widget.insert(tk.END, f"Status: {status}\n\n")
                    full_text_widget.insert(tk.END, "Decrypted Text:\n")
                    full_text_widget.insert(tk.END, decrypted_text)
                    full_text_widget.config(state=tk.DISABLED) # Make the text read-only
                    full_text_widget.pack(pady=10, padx=10, fill="both", expand="yes")

                    # Optional: Add a close button
                    close_button = tk.Button(detail_window, text="Close", command=detail_window.destroy)
                    close_button.pack(pady=5)

                else:
                    print("Error: Insufficient data in tags for full result.")
            except ValueError:
                print("Error: 'full_data' tag not found in selected item.")
        else:
            print("No full data tag found for selected item.")

    def get_all_problem_data(self):
        """
        Retrieves all problem data from the UI.
        """
        current_problems_data = {}
        for tab_name, widgets in self.problem_inputs.items():
            ciphertext = widgets['ciphertext'].get("1.0", tk.END).strip()
            keywords_string = widgets['keywords'].get("1.0", tk.END).strip()
            keywords = [k.strip() for k in keywords_string.replace(',', '\n').split('\n') if k.strip()]
            current_problems_data[tab_name] = {
                'ciphertext': ciphertext,
                'keywords': keywords
            }
        return current_problems_data

    def get_all_results_data(self):
        """
        Retrieves all results data from the UI's internal storage.
        """
        return self.results_data