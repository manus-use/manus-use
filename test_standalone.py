#!/usr/bin/env python3
"""Standalone test for AWS Bedrock - no dependencies except boto3."""

import json
import os


def test_bedrock_raw():
    """Test AWS Bedrock with raw boto3 - no other dependencies."""
    print("=== Testing Raw AWS Bedrock Connection ===")
    
    try:
        import boto3
    except ImportError:
        print("✗ boto3 not installed. Run: pip install boto3")
        return False
    
    try:
        # Create Bedrock client
        client = boto3.client(
            'bedrock-runtime',
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-west-2')
        )
        
        # Test with Claude Opus model
        model_id = "us.anthropic.claude-opus-4-20250514-v1:0"
        
        # Simple prompt
        messages = [
            {
                "role": "user",
                "content": "What is 2 + 2? Reply with just the number."
            }
        ]
        
        # Invoke model
        response = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "messages": messages,
                "max_tokens": 10,
                "temperature": 0.0,
                "anthropic_version": "bedrock-2023-05-31"
            })
        )
        
        # Parse response
        result = json.loads(response['body'].read())
        answer = result['content'][0]['text']
        
        print(f"✓ Model: {model_id}")
        print(f"✓ Response: {answer}")
        print("✓ AWS Bedrock is working correctly!")
        
        return True
        
    except Exception as e:
        print(f"✗ Bedrock test failed: {e}")
        
        # Check common issues
        if "AccessDeniedException" in str(e):
            print("\n  Issue: You don't have access to the model.")
            print("  Solution: Request access in AWS Bedrock console")
        elif "NoCredentialsError" in str(e):
            print("\n  Issue: AWS credentials not configured.")
            print("  Solution: Run 'aws configure'")
        elif "UnrecognizedClientException" in str(e):
            print("\n  Issue: Invalid AWS credentials.")
            print("  Solution: Check your AWS credentials")
            
        return False


def check_aws_setup():
    """Check AWS configuration."""
    print("=== Checking AWS Setup ===")
    
    # Check credentials
    try:
        import boto3
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✓ AWS Account: {identity['Account']}")
        print(f"✓ AWS User/Role: {identity['Arn']}")
        print(f"✓ AWS Region: {os.getenv('AWS_DEFAULT_REGION', 'us-west-2')}")
    except Exception as e:
        print(f"✗ AWS not configured: {e}")
        print("\nTo configure AWS:")
        print("1. Run: aws configure")
        print("2. Enter your AWS Access Key ID")
        print("3. Enter your AWS Secret Access Key")
        print("4. Enter region (e.g., us-west-2)")
        return False
    
    # Check Bedrock access
    try:
        import boto3
        bedrock = boto3.client('bedrock', region_name=os.getenv('AWS_DEFAULT_REGION', 'us-west-2'))
        
        # List available models
        response = bedrock.list_foundation_models()
        models = response.get('modelSummaries', [])
        
        claude_models = [m for m in models if 'claude' in m['modelId'].lower()]
        nova_models = [m for m in models if 'nova' in m['modelId'].lower()]
        
        if claude_models:
            print(f"\n✓ Available Claude models: {len(claude_models)}")
            for model in claude_models[:3]:  # Show first 3
                print(f"  - {model['modelId']}")
        
        if nova_models:
            print(f"\n✓ Available Nova models: {len(nova_models)}")
            for model in nova_models[:3]:  # Show first 3
                print(f"  - {model['modelId']}")
        
        if not claude_models and not nova_models:
            print("\n⚠ No Claude or Nova models available")
            print("  Please request access in AWS Bedrock console")
            
    except Exception as e:
        print(f"\n⚠ Could not list Bedrock models: {e}")
    
    return True


def main():
    """Run standalone tests."""
    print("ManusUse Standalone AWS Bedrock Test")
    print("=" * 40)
    
    # Check Python version
    import sys
    print(f"Python: {sys.version}")
    print("")
    
    # Check AWS setup
    if not check_aws_setup():
        return
    
    print("")
    
    # Test Bedrock
    if test_bedrock_raw():
        print("\n✅ Success! AWS Bedrock is working.")
        print("\nNext steps:")
        print("1. Run: ./setup_env.sh")
        print("2. Run: source venv/bin/activate")
        print("3. Run: python test_bedrock.py")
    else:
        print("\n❌ AWS Bedrock test failed.")
        print("\nTroubleshooting:")
        print("1. Check AWS credentials: aws configure list")
        print("2. Check Bedrock access: https://console.aws.amazon.com/bedrock/")
        print("3. Ensure you have access to Claude models")


if __name__ == "__main__":
    main()