import boto3
import json
import configparser


def create_iam_role(iam_client, role_name):
    """
    Creates an IAM role that allows Redshift to call other AWS services on your behalf.

    Args:
        iam_client: Boto3 IAM client object.
        role_name: Name for the new IAM role.

    Returns:
        The ARN of the newly created IAM role.
    """
    try:
        print('Creating a new IAM Role...')
        role = iam_client.create_role(
            Path='/',
            RoleName=role_name,
            Description='Allows Redshift to access other AWS services on your behalf.',
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'redshift.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            })
        )

        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        )

        role_arn = iam_client.get_role(RoleName=role_name)['Role']['Arn']
        print(f"IAM Role created with ARN: {role_arn}")
        return role_arn

    except Exception as e:
        print(f"Error creating IAM role: {e}")


def main():
    """
    Main function to configure and launch a Redshift cluster with an IAM role and open access port.
    """
    # Load configuration
    config = configparser.ConfigParser()
    config.read_file(open('dwh.cfg'))

    KEY = config.get('AWS', 'KEY')
    SECRET = config.get('AWS', 'SECRET')

    DWH_CLUSTER_TYPE = config.get("DWH", "DWH_CLUSTER_TYPE")
    DWH_NUM_NODES = config.get("DWH", "DWH_NUM_NODES")
    DWH_NODE_TYPE = config.get("DWH", "DWH_NODE_TYPE")
    DWH_CLUSTER_IDENTIFIER = config.get("DWH", "DWH_CLUSTER_IDENTIFIER")
    DWH_DB = config.get("DWH", "DWH_DB")
    DWH_DB_USER = config.get("DWH", "DWH_DB_USER")
    DWH_DB_PASSWORD = config.get("DWH", "DWH_DB_PASSWORD")
    DWH_PORT = config.get("DWH", "DWH_PORT")
    DWH_IAM_ROLE_NAME = config.get("DWH", "DWH_IAM_ROLE_NAME")

    # AWS clients
    ec2 = boto3.resource('ec2',
                         region_name='us-west-2',
                         aws_access_key_id=KEY,
                         aws_secret_access_key=SECRET)

    iam = boto3.client('iam',
                       region_name='us-west-2',
                       aws_access_key_id=KEY,
                       aws_secret_access_key=SECRET)

    redshift = boto3.client('redshift',
                            region_name="us-west-2",
                            aws_access_key_id=KEY,
                            aws_secret_access_key=SECRET)

    # Create IAM role
    role_arn = create_iam_role(iam, DWH_IAM_ROLE_NAME)

    # Launch Redshift cluster
    try:
        print("Creating Redshift cluster...")
        response = redshift.create_cluster(
            ClusterType=DWH_CLUSTER_TYPE,
            NodeType=DWH_NODE_TYPE,
            NumberOfNodes=int(DWH_NUM_NODES),
            DBName=DWH_DB,
            ClusterIdentifier=DWH_CLUSTER_IDENTIFIER,
            MasterUsername=DWH_DB_USER,
            MasterUserPassword=DWH_DB_PASSWORD,
            IamRoles=[role_arn]
        )
        print("Redshift cluster creation initiated.")
    except Exception as e:
        print(f"Error creating Redshift cluster: {e}")
        return

    # Open TCP port for access
    try:
        print("Authorizing cluster ingress...")
        cluster_props = redshift.describe_clusters(ClusterIdentifier=DWH_CLUSTER_IDENTIFIER)['Clusters'][0]
        vpc = ec2.Vpc(id=cluster_props['VpcId'])
        default_sg = list(vpc.security_groups.all())[0]

        default_sg.authorize_ingress(
            GroupName=default_sg.group_name,
            CidrIp='0.0.0.0/0',
            IpProtocol='TCP',
            FromPort=int(DWH_PORT),
            ToPort=int(DWH_PORT)
        )
        print("Ingress rule added.")
    except Exception as e:
        print(f"Error authorizing ingress: {e}")

    print("Redshift cluster setup completed. Check AWS console for details.")


if __name__ == "__main__":
    main()
