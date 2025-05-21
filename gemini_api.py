import requests
import os
import json

def process_cipher_result_with_gemini(cipher_result: str) -> dict:
    """
    Sends a cipher result to the Gemini API for review and determines if human review is needed.

    Args:
        cipher_result: The decrypted text result from the cipher.

    Returns:
        A dictionary containing the LLM's response and a boolean indicating if human review is needed.
    """
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        api_key = config.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in config.json.")
    except FileNotFoundError:
        raise FileNotFoundError("config.json not found. Please create it with your GEMINI_API_KEY.")
    except json.JSONDecodeError:
        raise ValueError("Error decoding config.json. Please ensure it is valid JSON.")
    except Exception as e:
        raise RuntimeError(f"Error reading config.json: {e}")


    # Define the API endpoint
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-04-17:generateContent?key={api_key}"

    headers = {
        "Content-Type": "application/json"
    }

    # Define the prompt for the LLM
    # Instruct the LLM to provide a JSON response with a 'review_needed' boolean field
    prompt = f"""
Review the following decrypted text result from a cipher:

"{cipher_result}"

Based on the content, determine if this result appears to be a potential answer to the cipher (i.e., coherent text, not random characters or gibberish) and requires review by a human expert.
Provide your response in JSON format with the following structure:
{{
  "review_needed": boolean,
  "llm_analysis": "Your analysis here"
}}

For example:
{{
  "review_needed": true,
  "llm_analysis": "The text appears to be coherent and could be a potential answer."
}}

Or:
{{
  "review_needed": false,
  "llm_analysis": "The text appears to be random characters or gibberish."
}}

Your JSON response:
"""

    payload = {
        # Structure of the payload depends on the specific Gemini API endpoint
        # This is a placeholder example
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        gemini_response = response.json()

        # Parse the LLM's JSON response
        # The exact structure depends on the Gemini API response format
        # This is a placeholder assuming the response contains the generated text directly
        try:
            # Assuming the LLM's JSON output is within the text of the first part of the first candidate
            llm_output_text = gemini_response['candidates'][0]['content']['parts'][0]['text']
            
            # Extract JSON string from markdown code block if present
            if llm_output_text.startswith("```json\n") and llm_output_text.endswith("\n```"):
                json_string = llm_output_text[len("```json\n"):-len("\n```")]
            else:
                json_string = llm_output_text # Assume it's just JSON if not in markdown

            # Attempt to parse the JSON string
            llm_parsed_response = json.loads(json_string)

            review_needed = llm_parsed_response.get("review_needed", False)
            llm_analysis = llm_parsed_response.get("llm_analysis", "No analysis provided.")

            return {
                "review_needed": review_needed,
                "llm_analysis": llm_analysis,
                "raw_gemini_response": gemini_response # Include raw response for debugging
            }
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            print(f"Error parsing Gemini response: {e}")
            # Handle cases where the LLM doesn't return the expected JSON format
            return {
                "review_needed": True, # Assume review is needed if parsing fails
                "llm_analysis": f"Failed to parse LLM response: {llm_output_text}",
                "raw_gemini_response": gemini_response
            }

    except requests.exceptions.RequestException as e:
        print(f"Error calling Gemini API: {e}")
        # Handle API call errors
        return {
            "review_needed": True, # Assume review is needed if API call fails
            "llm_analysis": f"Error calling Gemini API: {e}",
            "raw_gemini_response": None
        }

if __name__ == "__main__":
    # Example usage (for testing)
    test_result_sensitive = "The secret meeting will be held at 3 PM tomorrow at the usual location."
    test_result_normal = "ASDQWEGQWEQSGVQWETQYTIETIFEBVWGQYQYQYWSHDHQWYQWETQWFZSCQWDQER"

    print(f"Processing sensitive result: '{test_result_sensitive}'")
    review_status_sensitive = process_cipher_result_with_gemini(test_result_sensitive)
    print(f"Review status: {review_status_sensitive}")

    print(f"\nProcessing normal result: '{test_result_normal}'")
    review_status_normal = process_cipher_result_with_gemini(test_result_normal)
    print(f"Review status: {review_status_normal}")