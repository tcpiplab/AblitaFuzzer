#!/usr/bin/env python3
"""
Test script to verify Ollama API endpoints and understand the routing issue.
"""

import requests
import json

def test_native_ollama_api():
    """Test native Ollama /api/chat endpoint"""
    print("=== Testing Native Ollama API (/api/chat) ===")
    
    url = "http://api.promptmaker.local:11434/api/chat"
    payload = {
        "model": "huihui_ai/granite3.2-abliterated:8b",
        "messages": [
            {"role": "user", "content": "Say hello"}
        ],
        "stream": False
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_openai_compatible_api():
    """Test OpenAI-compatible /v1/chat/completions endpoint"""
    print("\n=== Testing OpenAI-Compatible API (/v1/chat/completions) ===")
    
    url = "http://api.promptmaker.local:11434/v1/chat/completions"
    payload = {
        "model": "huihui_ai/granite3.2-abliterated:8b",
        "messages": [
            {"role": "user", "content": "Say hello"}
        ]
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_openai_client_wrapper():
    """Test using OpenAI client with Ollama"""
    print("\n=== Testing OpenAI Client with Ollama ===")
    
    try:
        from openai import OpenAI
        
        # Create client pointing to Ollama
        client = OpenAI(
            base_url="http://api.promptmaker.local:11434/v1",
            api_key="not-needed"  # Ollama doesn't need API key
        )
        
        response = client.chat.completions.create(
            model="huihui_ai/granite3.2-abliterated:8b",
            messages=[
                {"role": "user", "content": "Say hello"}
            ]
        )
        
        print(f"Success: {response.choices[0].message.content}")
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("Testing Ollama API endpoints to debug routing issue...\n")
    
    # Test all three approaches
    native_works = test_native_ollama_api()
    openai_compat_works = test_openai_compatible_api()
    openai_client_works = test_openai_client_wrapper()
    
    print(f"\n=== Results ===")
    print(f"Native Ollama API (/api/chat): {'✓' if native_works else '✗'}")
    print(f"OpenAI-Compatible API (/v1/chat/completions): {'✓' if openai_compat_works else '✗'}")
    print(f"OpenAI Client Wrapper: {'✓' if openai_client_works else '✗'}")
    
    if openai_compat_works or openai_client_works:
        print(f"\nRecommendation: Use OpenAI-compatible endpoint")
    elif native_works:
        print(f"\nRecommendation: Use native Ollama endpoint")
    else:
        print(f"\nIssue: None of the endpoints are working. Check if Ollama is running and the model is loaded.")

if __name__ == "__main__":
    main()