#!/usr/bin/env python
import os
import sys
import re
from pathlib import Path
from typing import List, Tuple

def find_python_files(directory: str) -> List[Path]:
    """Find all Python files in directory"""
    return list(Path(directory).rglob("*.py"))

def update_imports(content: str) -> str:
    """Update import statements"""
    replacements = [
        (r'from pydantic import BaseModel', 'from pydantic.v1 import BaseModel'),
        (r'from anthropic import Client', 'from anthropic import Anthropic'),
        (r'client = anthropic.Client\(', 'client = anthropic.Anthropic('),
        (r'response.completion', 'message.content'),
        (r'df.append\(', 'pd.concat([df, '),
    ]
    
    for old, new in replacements:
        content = re.sub(old, new, content)
    return content

def update_streamlit_code(content: str) -> str:
    """Update Streamlit code"""
    # Update session state access
    content = re.sub(
        r"st\.session_state\['([^']+)'\]",
        r"st.session_state.\1",
        content
    )
    return content

def backup_file(file_path: Path) -> None:
    """Create backup of file"""
    backup_path = file_path.with_suffix('.py.bak')
    file_path.rename(backup_path)

def migrate_file(file_path: Path) -> Tuple[bool, str]:
    """Migrate a single file"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Create backup
        backup_file(file_path)
        
        # Apply migrations
        new_content = content
        new_content = update_imports(new_content)
        new_content = update_streamlit_code(new_content)
        
        # Write updated content
        with open(file_path, 'w') as f:
            f.write(new_content)
        
        return True, f"Successfully migrated {file_path}"
    except Exception as e:
        return False, f"Error migrating {file_path}: {str(e)}"

def main():
    """Main migration script"""
    if len(sys.argv) != 2:
        print("Usage: python migrate.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a directory")
        sys.exit(1)
    
    print(f"Starting migration of {directory}")
    files = find_python_files(directory)
    
    results = []
    for file_path in files:
        success, message = migrate_file(file_path)
        results.append((success, message))
    
    # Print summary
    print("\nMigration Summary:")
    successful = sum(1 for success, _ in results if success)
    print(f"Successfully migrated: {successful}/{len(results)} files")
    
    print("\nDetails:")
    for success, message in results:
        status = "✓" if success else "✗"
        print(f"{status} {message}")

if __name__ == '__main__':
    main() 