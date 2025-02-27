#!/usr/bin/env python
import boto3
import click
import yaml
import os

@click.command()
@click.option('--region', default='us-west-2', help='AWS region')
@click.option('--cluster-name', default='llm-scanner', help='ECS cluster name')
@click.option('--config', default='config.yaml', help='Configuration file')
def deploy_aws(region, cluster_name, config):
    """Deploy to AWS ECS"""
    # Load configuration
    with open(config) as f:
        cfg = yaml.safe_load(f)
    
    # Initialize AWS clients
    ecs = boto3.client('ecs', region_name=region)
    ec2 = boto3.client('ec2', region_name=region)
    rds = boto3.client('rds', region_name=region)
    
    # Create VPC and subnets
    vpc = create_vpc(ec2)
    subnets = create_subnets(ec2, vpc['VpcId'])
    
    # Create RDS instance
    db = create_database(rds, vpc['VpcId'], subnets)
    
    # Create ECS cluster
    cluster = ecs.create_cluster(clusterName=cluster_name)
    
    # Create task definitions
    task_def = create_task_definitions(ecs, cfg, db)
    
    # Create services
    create_services(ecs, cluster['cluster']['clusterArn'], task_def)
    
    click.echo("Deployment complete!")

def create_vpc(ec2):
    """Create VPC for the application"""
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    return vpc

def create_subnets(ec2, vpc_id):
    """Create subnets in the VPC"""
    subnet1 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock='10.0.1.0/24',
        AvailabilityZone='us-west-2a'
    )
    subnet2 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock='10.0.2.0/24',
        AvailabilityZone='us-west-2b'
    )
    return [subnet1, subnet2]

def create_database(rds, vpc_id, subnets):
    """Create RDS database"""
    subnet_ids = [s['Subnet']['SubnetId'] for s in subnets]
    db_subnet_group = rds.create_db_subnet_group(
        DBSubnetGroupName='scanner-db-subnet',
        DBSubnetGroupDescription='Subnet group for Scanner DB',
        SubnetIds=subnet_ids
    )
    
    db = rds.create_db_instance(
        DBName='scanner',
        DBInstanceIdentifier='scanner-db',
        AllocatedStorage=20,
        DBInstanceClass='db.t3.micro',
        Engine='postgres',
        MasterUsername='scanner',
        MasterUserPassword=os.getenv('DB_PASSWORD'),
        VpcSecurityGroupIds=[vpc_id],
        DBSubnetGroupName=db_subnet_group['DBSubnetGroup']['DBSubnetGroupName']
    )
    return db

def create_task_definitions(ecs, cfg, db):
    """Create ECS task definitions"""
    # Task definition for API
    api_task = ecs.register_task_definition(
        family='scanner-api',
        containerDefinitions=[
            {
                'name': 'api',
                'image': cfg['api']['image'],
                'environment': [
                    {
                        'name': 'DATABASE_URL',
                        'value': f"postgresql://scanner:{os.getenv('DB_PASSWORD')}@{db['DBInstance']['Endpoint']['Address']}/scanner"
                    }
                ]
            }
        ]
    )
    return api_task

def create_services(ecs, cluster_arn, task_def):
    """Create ECS services"""
    ecs.create_service(
        cluster=cluster_arn,
        serviceName='scanner-api',
        taskDefinition=task_def['taskDefinition']['taskDefinitionArn'],
        desiredCount=2
    )

if __name__ == '__main__':
    deploy_aws() 