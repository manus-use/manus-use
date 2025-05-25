#!/usr/bin/env python3
"""Test AWS Bedrock with Amazon Nova models."""

import json
import os


def test_nova_model():
    """Test Amazon Nova model."""
    print("=== Testing Amazon Nova Model ===")
    
    try:
        import boto3
    except ImportError:
        print("✗ boto3 not installed")
        return False
    
    try:
        # Create Bedrock client
        client = boto3.client(
            'bedrock-runtime',
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
        )
        
        # Try Nova Lite model (usually has better availability)
        model_id = "amazon.nova-lite-v1:0"
        
        # Simple prompt
        messages = [
            {
                "role": "user",
                "content": [{"text": "What is 2 + 2? Reply with just the number."}]
            }
        ]
        
        # Invoke model with Nova-specific format
        response = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "schemaVersion": "messages-v1",
                "messages": messages,
                "inferenceConfig": {
                    "max_new_tokens": 10,
                    "temperature": 0.0
                }
            })
        )
        
        # Parse response
        result = json.loads(response['body'].read())
        
        # Extract text from Nova response format
        if 'output' in result and 'message' in result['output']:
            content = result['output']['message']['content']
            if isinstance(content, list) and len(content) > 0:
                answer = content[0].get('text', 'No text found')
            else:
                answer = str(content)
        else:
            answer = str(result)
        
        print(f"✓ Model: {model_id}")
        print(f"✓ Response: {answer}")
        print("✓ Amazon Nova is working correctly!")
        
        return True
        
    except Exception as e:
        error_str = str(e)
        print(f"✗ Nova test failed: {e}")
        
        if "AccessDeniedException" in error_str:
            print("\nTrying Nova Pro model instead...")
            return test_nova_pro()
        
        return False


def test_nova_pro():
    """Test Amazon Nova Pro model."""
    try:
        import boto3
        
        client = boto3.client(
            'bedrock-runtime',
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
        )
        
        # Try Nova Pro
        model_id = "amazon.nova-pro-v1:0"
        
        response = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "schemaVersion": "messages-v1",
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": "What is 2 + 2?"}]
                    }
                ],
                "inferenceConfig": {
                    "max_new_tokens": 10,
                    "temperature": 0.0
                }
            })
        )
        
        result = json.loads(response['body'].read())
        print(f"✓ Nova Pro working!")
        print(f"✓ Response: {result}")
        
        return True
        
    except Exception as e:
        print(f"✗ Nova Pro also failed: {e}")
        return False


def check_model_access():
    """Check which models we have access to."""
    print("=== Checking Model Access ===")
    
    try:
        import boto3
        
        bedrock = boto3.client('bedrock', region_name=os.getenv('AWS_DEFAULT_REGION', 'us-west-2'))
        
        # Get foundation model details
        try:
            # Try to get details for specific models
            models_to_check = [
                "amazon.nova-lite-v1:0",
                "amazon.nova-pro-v1:0",
                "anthropic.claude-3-5-sonnet-20241022-v2:0"
            ]
            
            for model_id in models_to_check:
                try:
                    response = bedrock.get_foundation_model(modelIdentifier=model_id)
                    model_details = response.get('modelDetails', {})
                    print(f"\n✓ {model_id}:")
                    print(f"  Status: Available")
                    print(f"  Provider: {model_details.get('providerName', 'Unknown')}")
                except Exception as e:
                    if "ResourceNotFoundException" in str(e):
                        print(f"\n✗ {model_id}: Not found in this region")
                    else:
                        print(f"\n✗ {model_id}: {str(e)[:100]}")
                        
        except Exception as e:
            print(f"Could not check individual models: {e}")
            
    except Exception as e:
        print(f"✗ Could not create Bedrock client: {e}")


def main():
    """Run tests."""
    print("Amazon Nova Model Test for ManusUse")
    print("=" * 40)
    
    check_model_access()
    
    print("\n")
    
    if test_nova_model():
        print("\n✅ Success! We can use Amazon Nova models.")
        print("\nUpdating ManusUse config to use Nova...")
        
        # Show how to update config
        print("\nUpdate your config/config.bedrock.toml:")
        print('model = "amazon.nova-lite-v1:0"  # or amazon.nova-pro-v1:0')


if __name__ == "__main__":
    main()