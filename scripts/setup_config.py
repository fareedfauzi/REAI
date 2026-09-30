import os
import sys
import json
import urllib.request
import urllib.error

def test_api(provider, model, api_key):
    print(f"\n[Testing API] Provider: {provider}, Model: {model}...")
    if provider == "openai":
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": "Hello, this is a test from REAI setup."}],
            "max_tokens": 10
        }
    elif provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": "Hello, this is a test from REAI setup."}],
            "max_tokens": 10
        }
    elif provider == "ollama":
        url = "http://localhost:11434/api/chat"
        headers = {"Content-Type": "application/json"}
        data = {
            "model": model,
            "messages": [{"role": "user", "content": "Hello, this is a test from REAI setup."}],
            "stream": False
        }
    else:
        print(f"[!] Automated testing for provider '{provider}' is not supported by this script.")
        print("[!] Skipping API test.")
        return True

    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status == 200:
                print("[+] API key and model are working correctly!")
                return True
    except urllib.error.HTTPError as e:
        print(f"[-] API test failed! HTTP Error {e.code}: {e.reason}")
        error_body = e.read().decode('utf-8')
        try:
            print(f"[-] Details: {json.loads(error_body)}")
        except:
            print(f"[-] Details: {error_body}")
        return False
    except urllib.error.URLError as e:
        print(f"[-] API test failed! Network Error: {e.reason}")
        return False
    except Exception as e:
        print(f"[-] API test failed! Error: {e}")
        return False
    return False

def main():
    print("\n" + "="*50)
    print(" REAI Configuration Setup ")
    print("="*50)
    
    ida_path = input("\nEnter the path to your IDA Pro installation\n(e.g. C:/Program Files/IDA Professional 9.3): ").strip()
    # Normalize path
    ida_path = ida_path.replace("\\", "/")
    
    print("\nAvailable AI Providers: openai, anthropic, openai-compatible, lmstudio, ollama, hermes")
    provider = input("Enter AI provider [default: openai]: ").strip() or "openai"
    
    model = input("Enter the model name (e.g. gpt-4o-mini, claude-3-5-sonnet-20240620)\n[default: gpt-4o-mini]: ").strip() or "gpt-4o-mini"
    
    api_key = ""
    if provider not in ["ollama", "lmstudio"]:
        api_key = input("Enter your API key: ").strip()
    
    print("\nGenerating reai.toml...")
    
    toml_content = f"""[ida]
path = "{ida_path}"

[ai]
provider = "{provider}"
model = "{model}"
api-key = "{api_key}"
"""
    
    with open("reai.toml", "w", encoding="utf-8") as f:
        f.write(toml_content)
    
    print("[+] reai.toml created successfully.")
    
    # Test the API
    if provider in ["openai", "anthropic", "ollama"]:
        success = test_api(provider, model, api_key)
        if not success:
            print("\n[!] API test failed. Please check your reai.toml configuration and ensure your API key and model name are correct.")
            sys.exit(1)
            
    print("\n[+] Configuration is complete and verified!")

if __name__ == "__main__":
    main()
