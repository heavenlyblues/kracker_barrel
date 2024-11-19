import openai
import os

# Load the API key from a file
def load_api_key(filepath="~/.ssh/id_openai"):
    try:
        with open(os.path.expanduser(filepath), "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        raise Exception("API key file not found. Please provide a valid OpenAI API key.")

# Set OpenAI API key
openai.api_key = load_api_key()

# Analyze a single password
def analyze_password(password):
    prompt = f"Is '{password}' a realistic and secure password? Reply 'yes' or 'no' and explain why."
    try:
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=50,
            n=1,
            stop=None,
            temperature=0.7,  # Adjust creativity level
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"Error analyzing password '{password}': {e}"

# Analyze a batch of passwords
def analyze_passwords(password_list):
    results = {}
    for password in password_list:
        analysis = analyze_password(password)
        results[password] = analysis
    return results

# Example usage
if __name__ == "__main__":
    passwords = ["123456", "secure-password!2023", "iloveyou", "P@ssw0rd"]
    analysis_results = analyze_passwords(passwords)

    for password, result in analysis_results.items():
        print(f"Password: {password}\nAnalysis: {result}\n")




# from transformers import pipeline
# import csv

# # Initialize a Hugging Face GPT-2 pipeline for text generation
# generator = pipeline("text-generation", model="gpt2")

# def score_passwords_with_ai(input_csv, output_csv, threshold=0.5):
#     """
#     Analyze passwords using GPT-2 and filter based on AI scores.
#     """
#     filtered_passwords = []

#     with open(input_csv, "r", encoding="utf-8") as infile:
#         reader = csv.DictReader(infile)
#         for row in reader:
#             password = row["password"]
#             count = int(row["count"])

#             # Use GPT-2 to score the likelihood of the password
#             prompt = f"Is '{password}' a realistic password?"
#             result = generator(prompt, max_length=50, num_return_sequences=1)
#             ai_score = "yes" in result[0]["generated_text"].lower()

#             # Filter passwords based on AI score and threshold
#             if ai_score:
#                 filtered_passwords.append((password, count))

#     # Write filtered passwords to a new CSV
#     with open(output_csv, "w", encoding="utf-8") as outfile:
#         writer = csv.writer(outfile)
#         writer.writerow(["password", "count"])
#         writer.writerows(filtered_passwords)

#     print(f"Filtered passwords saved to {output_csv}")

# # Example usage
# score_passwords_with_ai("updated_passwords.csv", "filtered_passwords.csv")