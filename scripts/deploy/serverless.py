#!/usr/bin/env python
import click
import subprocess
import os
import json
from pathlib import Path

@click.group()
def cli():
    """Deployment CLI for serverless platforms"""
    pass

@cli.command()
@click.option('--site-name', help='Netlify site name')
def deploy_netlify(site_name):
    """Deploy to Netlify"""
    # Check for Netlify CLI
    if subprocess.run(['which', 'netlify']).returncode != 0:
        click.echo("Installing Netlify CLI...")
        subprocess.run(['npm', 'install', '-g', 'netlify-cli'])
    
    # Initialize Netlify if needed
    if not Path('.netlify').exists():
        subprocess.run(['netlify', 'init'])
    
    # Build project
    click.echo("Building project...")
    subprocess.run(['pip', 'install', '-r', 'requirements.txt'])
    subprocess.run(['python', 'setup.py', 'install'])
    
    # Deploy
    click.echo("Deploying to Netlify...")
    cmd = ['netlify', 'deploy', '--prod']
    if site_name:
        cmd.extend(['--site', site_name])
    subprocess.run(cmd)

@cli.command()
def deploy_vercel():
    """Deploy to Vercel"""
    # Check for Vercel CLI
    if subprocess.run(['which', 'vercel']).returncode != 0:
        click.echo("Installing Vercel CLI...")
        subprocess.run(['npm', 'install', '-g', 'vercel'])
    
    # Ensure we have required files
    if not Path('vercel.json').exists():
        click.echo("Creating vercel.json...")
        with open('vercel.json', 'w') as f:
            json.dump({
                "version": 2,
                "builds": [
                    {
                        "src": "scanner/ui/api.py",
                        "use": "@vercel/python"
                    }
                ],
                "routes": [
                    {
                        "src": "/api/(.*)",
                        "dest": "scanner/ui/api.py"
                    }
                ]
            }, f, indent=2)
    
    # Deploy
    click.echo("Deploying to Vercel...")
    subprocess.run(['vercel', '--prod'])

if __name__ == '__main__':
    cli() 