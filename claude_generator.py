import boto3
import json
import os
import requests
import subprocess
import tempfile
from botocore.config import Config


def get_bedrock_client():
  config = Config(
      read_timeout=120,  # Increase from default (~60s)
      connect_timeout=10,  # Optional, you can tweak this too
      retries={
          'max_attempts': 3,
          'mode': 'standard'
      }
  )
  return boto3.client('bedrock-runtime', region_name=os.environ['AWS_DEFAULT_REGION'], config=config)

def read_file_safely(filepath, max_lines=100):
    """Read file content safely, limiting lines for context"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                return ''.join(lines[:max_lines]) + f'\n... (truncated, {len(lines)-max_lines} more lines)'
            return ''.join(lines)
    except Exception as e:
        return f"Error reading file: {str(e)}"

def analyze_codebase():
    """Analyze the current codebase structure"""
    context = ""
    
    # Read project context
    if os.path.exists('project_context.txt'):
        context += read_file_safely('project_context.txt')
    
    # Read key configuration files for Go/mobile project
    key_files = ['README.md', 'INSTALL.md', 'go/go.mod', 'Makefile', 'Manifest.yml']
    for file in key_files:
        if os.path.exists(file):
            context += f"\n\n=== {file} ===\n"
            context += read_file_safely(file, 50)
    
    # Read Android configuration files
    android_files = ['android/build.gradle', 'android/app/build.gradle', 'android/settings.gradle']
    for file in android_files:
        if os.path.exists(file):
            context += f"\n\n=== {file} ===\n"
            context += read_file_safely(file, 30)
    
    # Read iOS configuration files
    ios_files = ['ios/Bridge/GomobileIPFS/Info.plist']
    for file in ios_files:
        if os.path.exists(file):
            context += f"\n\n=== {file} ===\n"
            context += read_file_safely(file, 30)
    
    # Sample some source files to understand patterns
    if os.path.exists('codebase_files.txt'):
        with open('codebase_files.txt', 'r') as f:
            files = [line.strip() for line in f.readlines()[:15]]  # First 15 files
        
        for file in files:
            if os.path.exists(file):
                context += f"\n\n=== {file} ===\n"
                context += read_file_safely(file, 40)
    
    return context

def generate_code_with_claude(task_description, codebase_context):
    client = get_bedrock_client()
    
    prompt = f"""
You are an expert software developer working on gomobile-ipfs, a Go-based mobile IPFS implementation with Android and iOS bindings.

This project provides packages for Android, iOS and React-Native that allow running and using an IPFS node on mobile devices.

TASK: {task_description}

CURRENT CODEBASE CONTEXT:
{codebase_context}

Please generate the necessary code changes to implement the requested feature. Your response should include:

1. **FILES_TO_CREATE**: List any new files that need to be created with their full paths
2. **FILES_TO_MODIFY**: List any existing files that need to be modified
3. **CODE_CHANGES**: Provide the actual code for new files or specific changes for existing files
4. **INSTRUCTIONS**: Any additional setup or configuration steps needed

Follow these guidelines:
- Use Go 1.18+ syntax and best practices
- Follow gomobile binding patterns for cross-platform compatibility
- Maintain consistency with existing IPFS and libp2p patterns
- Include proper error handling and logging
- Use appropriate Go types and interfaces
- For Android: Use Java/Kotlin patterns compatible with the existing bridge
- For iOS: Use Swift/Objective-C patterns compatible with the existing bridge
- Consider mobile constraints (battery, network, storage)
- Follow the existing project structure and build system (Makefile)
- Ensure compatibility with the existing IPFS node configuration

Project Structure Context:
- go/: Contains the Go core implementation and bindings
- android/: Contains Android-specific bridge and demo app
- ios/: Contains iOS-specific bridge and demo app
- The project uses gomobile for generating mobile bindings
- Build system uses Make with targets for different platforms

Format your response clearly with sections for each file change.
"""

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 8000,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
    
    response = client.invoke_model(
        body=json.dumps(body),
        modelId=os.environ.get('AWS_BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0'),
        accept='application/json',
        contentType='application/json'
    )
    
    response_body = json.loads(response.get('body').read())
    return response_body['content'][0]['text']

def create_branch_and_commit(branch_name, generated_content):
    """Create a new branch and commit the generated code"""
    try:

        subprocess.run(['git', 'config', 'user.name', 'Claude Bot'], check=True)
        subprocess.run(['git', 'config', 'user.email', 'claude-bot@example.com'], check=True)

        # Create and checkout new branch
        subprocess.run(['git', 'checkout', '-b', branch_name], check=True)
        
        # Create a summary file with the generated content
        with open('CLAUDE_GENERATED.md', 'w') as f:
            f.write(f"# Claude Generated Code\n\n")
            f.write(f"**Task**: {os.environ['TASK_DESCRIPTION']}\n\n")
            f.write(f"**Generated on**: {subprocess.check_output(['date']).decode().strip()}\n\n")
            f.write("## Generated Content\n\n")
            f.write("```\n")
            f.write(generated_content)
            f.write("\n```\n")
        
        # Stage and commit changes
        subprocess.run(['git', 'add', '.'], check=True)
        subprocess.run(['git', 'commit', '-m', f'Add Claude generated code\n\nTask: {os.environ["TASK_DESCRIPTION"]}\n\nGenerated by Claude AI via Amazon Bedrock'], check=True)
        
        # Push branch
        subprocess.run(['git', 'push', '-u', 'origin', branch_name], check=True)
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"Git operation failed: {e}")
        return False

def create_pull_request(branch_name, task_description, generated_content):
    """Create a pull request with the generated code"""
    github_token = os.environ['GITHUB_TOKEN']
    repo = os.environ['GITHUB_REPOSITORY']
    
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    pr_body = f"""## 🤖 Claude AI Generated Code

**Task Description:** {task_description}

This pull request contains code generated by Claude AI via Amazon Bedrock based on the requested feature.

## Generated Changes

```
{generated_content[:2000]}{'...' if len(generated_content) > 2000 else ''}
```

## Review Notes

- Please review the generated code carefully
- Test the functionality before merging
- Make any necessary adjustments for your specific requirements
- Check for integration with existing codebase

---
*This PR was created automatically by Claude AI*
"""
    
    pr_data = {
        'title': f'🤖 Claude Generated: {task_description[:50]}{"..." if len(task_description) > 50 else ""}',
        'head': branch_name,
        'base': 'master',
        'body': pr_body
    }
    
    url = f'https://api.github.com/repos/{repo}/pulls'
    response = requests.post(url, headers=headers, json=pr_data)
    
    if response.status_code == 201:
        pr_url = response.json()['html_url']
        print(f"✅ Pull request created: {pr_url}")
        return pr_url
    else:
        print(f"❌ Failed to create PR: {response.status_code}")
        print(response.text)
        return None

def main():
    task_description = os.environ['TASK_DESCRIPTION']
    branch_name = os.environ['TARGET_BRANCH']
    
    print(f"🚀 Generating code for task: {task_description}")
    
    # Analyze codebase
    print("📊 Analyzing codebase...")
    codebase_context = analyze_codebase()
    
    # Generate code with Claude
    print("🧠 Generating code with Claude...")
    generated_content = generate_code_with_claude(task_description, codebase_context)
    
    # Create branch and commit
    print(f"🌿 Creating branch: {branch_name}")
    if create_branch_and_commit(branch_name, generated_content):
        # Create pull request
        print("📝 Creating pull request...")
        pr_url = create_pull_request(branch_name, task_description, generated_content)
        
        if pr_url:
            print(f"🎉 Code generation completed successfully!")
            print(f"Pull request: {pr_url}")
        else:
            print("⚠️ Code generated but PR creation failed")
    else:
        print("❌ Failed to create branch and commit changes")

if __name__ == "__main__":
    main()
