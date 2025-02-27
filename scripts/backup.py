#!/usr/bin/env python
import os
import subprocess
from datetime import datetime
import boto3  # For AWS S3 backup

def backup_database():
    """Backup PostgreSQL database"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f"backup_{timestamp}.sql"
    
    # Get database URL from environment
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise ValueError("DATABASE_URL not set")
    
    # Create backup
    subprocess.run([
        "pg_dump",
        "-f", backup_file,
        db_url
    ])
    
    # Upload to S3 if configured
    if os.getenv("AWS_BUCKET_NAME"):
        s3 = boto3.client('s3')
        s3.upload_file(
            backup_file,
            os.getenv("AWS_BUCKET_NAME"),
            f"backups/database/{backup_file}"
        )

def backup_config():
    """Backup configuration files"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = f"config_backup_{timestamp}"
    
    # Create backup directory
    os.makedirs(backup_dir)
    
    # Copy configuration files
    files_to_backup = [".env", "config.yaml"]
    for file in files_to_backup:
        if os.path.exists(file):
            subprocess.run(["cp", file, backup_dir])

if __name__ == "__main__":
    backup_database()
    backup_config() 