#This script returns the list of missing commands (without repeats and boundaries, use cmd XenonRecomp output for this input.txt
def process_text_file(input_file):
    # Dictionary to store unique strings
    unique_strings = {}
    
    try:
        # Read the input file
        with open(input_file, 'r', encoding='utf-8') as file:
            for line in file:
                # Check if line contains ": "
                if ": " in line:
                    # Split the line at ": " and take the second part
                    parts = line.split(": ", 1)
                    if len(parts) > 1:
                        # Get the string after ": " and strip whitespace
                        string_after = parts[1].strip()
                        # Add to dictionary if not empty and starts with a letter
                        if string_after and string_after[0].isalpha():
                            unique_strings[string_after] = True
        
        # Write unique strings to output.txt
        with open('output.txt', 'w', encoding='utf-8') as output_file:
            for string in unique_strings.keys():
                output_file.write(f"{string}\n")
                
        print(f"Processing complete. Found {len(unique_strings)} unique strings.")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    input_file = "input.txt"  # Change this to your input file name
    process_text_file(input_file) 
