import base64
import hashlib
import os


def generate_key_stream(password: str, length: int) -> bytes:
    """Derives a repeating key stream from the user's password."""
    key_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return (key_hash * (length // len(key_hash) + 1))[:length]


def protect_file(input_path: str, password: str) -> str:
    """Converts file content into a protected .locked format."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")

    with open(input_path, "rb") as file:
        original_data = file.read()

    # Create a verification signature so wrong passwords are caught on restore
    signature = hashlib.sha256(password.encode("utf-8")).digest()[:8]
    payload = signature + original_data

    key_stream = generate_key_stream(password, len(payload))
    protected_bytes = bytes(a ^ b for a, b in zip(payload, key_stream))
    encoded_data = base64.b64encode(protected_bytes)

    output_path = input_path + ".locked"
    with open(output_path, "wb") as file:
        file.write(encoded_data)

    return output_path


def restore_file(locked_path: str, password: str) -> str:
    """Restores a .locked file back to its original content."""
    if not os.path.exists(locked_path):
        raise FileNotFoundError(f"File not found: {locked_path}")

    with open(locked_path, "rb") as file:
        encoded_data = file.read()

    protected_bytes = base64.b64decode(encoded_data)
    key_stream = generate_key_stream(password, len(protected_bytes))
    decrypted_payload = bytes(a ^ b for a, b in zip(protected_bytes, key_stream))

    # Verify password signature
    expected_signature = hashlib.sha256(password.encode("utf-8")).digest()[:8]
    if decrypted_payload[:8] != expected_signature:
        raise ValueError("Incorrect password or corrupted file.")

    original_data = decrypted_payload[8:]
    if locked_path.endswith(".locked"):
        output_path = locked_path[:-7]
    else:
        output_path = locked_path + ".restored"

    with open(output_path, "wb") as file:
        file.write(original_data)

    return output_path


def main():
    print("=== File Protection Utility ===")
    print("1. Protect (Lock) a file")
    print("2. Restore (Unlock) a file")
    choice = input("\nSelect an option (1 or 2): ").strip()

    if choice not in {"1", "2"}:
        print("Invalid choice. Please enter 1 or 2.")
        return

    file_path = input("Enter the file path: ").strip()
    password = input("Enter secret password: ").strip()

    if not password:
        print("Password cannot be empty.")
        return

    try:
        if choice == "1":
            saved_path = protect_file(file_path, password)
            print(f"\nSuccess! Protected file saved as: {saved_path}")
        else:
            restored_path = restore_file(file_path, password)
            print(f"\nSuccess! File restored as: {restored_path}")
    except Exception as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
