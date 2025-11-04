import json
import boto3
import logging
import datetime
import traceback
import snowflake.connector
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Function to Rotate/Create Snowflake Credentials (RSA or PAT)---
def credential_creation_rotation(client, admin_user, admin_pass, admin_account, sf_user, sf_role, secret_dict, secret_name, secret_arn, sf_credential_type):
    '''
    Function connects to Snowflake instance and calls the METADATA.CYBER.SP_MANAGE_PAT_LIFECYCLE() stored procedure to perform the following - 
        1. If the sf_user and sf_role combination does not exist in child table METADATA.CYBER.ACTIVE_SERVICE_USER_ROLE_PAT_STATUS, then throw an error.
            You need to add AUTHENTICATION_TYPE = "KEY PAIR" or "ACCESS TOKEN" in parent table METADATA.CYBER.ACTIVE_SERVICE_USER_STATUS 
            and update the child table by calling the procedure METADATA.CYBER.SP_REFRESH_ACTIVE_SERVICE_USERS_TABLES().
        2. For an sf_user and sf_role combination, if an active credential does not exist, then create a new credential.
        3. For an sf_user and sf_role combination, if an active credential exists, then auto rotate the exisitng credential.

    :param client: Connectivity session created with AWS Secrets Manager
    :param admin_user: Snowflake account username of the Admin
    :param admin_pass: Snowflake account password of the Admin
    :param admin_account: Snowflake account of the Admin
    :param sf_role: User name of the user
    :param sf_role: Role name associated with the user
    :param secret_dict: Contains dictionary of all the key values stored in a Secret
    :param secret_name: Name of the secret in Secrets Manager
    :return: newly generated credential

    '''
    # Load the Privatekey from Secrets Manager and convert to bytes
    pem_key_bytes =admin_pass.encode('utf-8')
    # Load PEM key
    private_key = serialization.load_pem_private_key(
        pem_key_bytes,
        password=None,
        backend=default_backend()
    )

    # Convert to DER bytes
    der_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    admin_ctx = snowflake.connector.connect(
        user=admin_user,
        #password=admin_pass,
        private_key=der_key_bytes,
        account=admin_account
    )
    admin_cs = admin_ctx.cursor()
    try:
        warehouse_name = os.environ.get("warehouse_name")
        admin_cs.execute(f"USE WAREHOUSE {warehouse_name};") # Setting up the Snowflake warehouse
        if sf_credential_type == "KEY_PAIR":
            logger.info("Executing RSA key pair lifecycle procedure.")
            sql = f"CALL METADATA.CYBER.SP_USM_MANAGE_MASTER_LIFECYCLE('{sf_user}', '-', 'LAMBDA', 'KEY PAIR');" # Call Snowflake SP to perform RSA Key/PAT token creation/auto rotation.
        elif sf_credential_type == "ACCESS_TOKEN":
            logger.info("Executing PAT access token lifecycle procedure.")
            sql = f"CALL METADATA.CYBER.SP_USM_MANAGE_MASTER_LIFECYCLE('{sf_user}', '{sf_role}', 'LAMBDA', 'ACCESS TOKEN');" # Call Snowflake SP to perform RSA Key/PAT token creation/auto rotation.
        admin_cs.execute(sql)
        result = admin_cs.fetchone()
        new_credential = result[0] if result else None

        if not new_credential:
            raise RuntimeError("No token_secret returned from Snowflake.")
        elif 'error' in new_credential.lower():
            raise RuntimeError(f"Rotation error: {new_credential}")

        if sf_credential_type == "KEY_PAIR":  
            logger.info("RSA Key pair rotation successful, updating Secrets Manager.")
            secret_dict.update({
                "private_key": new_credential,
                "USERNAME": sf_user,
                "user": sf_user,
                "updatedate": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            })
        elif sf_credential_type == "ACCESS_TOKEN":
            logger.info("PAT Access token rotation successful, updating Secrets Manager.")
            secret_dict.update({
                "sfPassword": new_credential,
                "PASSWORD": new_credential,
                "password": new_credential,
                "USERNAME": sf_user,
                "user": sf_user,
                "updatedate": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            })

        client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(secret_dict)
        )
        logger.info("Secret updated with new credentials.")
    finally:
        admin_cs.close()
        admin_ctx.close()

    return new_credential

# --- Email Notification in case of failure after 2 attempts ---
def send_failure_notification(event, error_message, sf_credential_type):
    '''
    Function sends out email notification in case of failure after 2nd attempt only. 
    Details of whom to send the email notification is provided in the SNS_TOPIC_ARN.
    '''
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not sns_topic_arn:
        logger.warning("SNS_TOPIC_ARN not set. Skipping notification.")
        return

    sns = boto3.client("sns")

    if sf_credential_type == "KEY_PAIR":
        subject = f"Snowflake RSA Key Pair Rotation Failure"
        message = f"An error occurred during key pair rotation.\n\nEvent: {json.dumps(event, indent=2)}\n\nError:\n{error_message}"
    elif sf_credential_type == "ACCESS_TOKEN":
        subject = f"Snowflake PAT Rotation Failure"
        message = f"An error occurred during PAT rotation.\n\nEvent: {json.dumps(event, indent=2)}\n\nError:\n{error_message}"

    try:
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info("SNS notification sent.")
    except Exception as sns_err:
        logger.error(f"Failed to send SNS notification: {sns_err}")


# --- Lambda Handler ---
def lambda_handler(event, context):
    """
    Function lambda_handler is the entry point of the code.
    This function establishes connectivity with AWS Secrets Manager, gets relevant details from Secrets manager, 
    and based on the values, performs the Snowflake RSA key pair/PAT access token auto rotation.

    :param event: The data from the event that triggered the function
    :param context: The data about the execution environment of the function
    :return: returns a dictionary with statusCode and body containing more details of the lambda function output
    """ 
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    logger.info(f"Lambda invoked by: {identity['Arn']}")

    try:
        # Get all the details of Secret invoked by the lambda function from Secrets Manager
        client = boto3.client("secretsmanager", region_name="us-east-1")
        secret_id = event.get("SecretId")
        if not secret_id:
            raise ValueError("Missing 'SecretId' in event.")
        logger.info(f"Processing secret: {secret_id}")

        secret_response = client.get_secret_value(SecretId=secret_id)
        secret_arn = secret_response["ARN"]
        secret_name = secret_response.get("Name")
        if not secret_name:
            raise ValueError("Missing 'Name' in secret response.")
        secret_string = secret_response.get("SecretString", "{}")
        secret_dict = json.loads(secret_string)

        logger.info(f"Processing secret name: {secret_name}")

        required_keys = ["sfUser", "account", "environment", "sfRole"]
        for key in required_keys:
            if key not in secret_dict:
                raise ValueError(f"Missing required field '{key}' in secret.")

        sf_user = secret_dict["sfUser"]
        sf_account = secret_dict["account"]
        sf_env = secret_dict["environment"]
        sf_role = secret_dict["sfRole"]
        syncflag = secret_dict.get("syncflag", "false")
        retry_attempted = secret_dict.get("rotationRetryAttempted", "0")
        sf_password_cred = secret_dict.get("sfPassword", "0")
        sf_private_key_cred = secret_dict.get("private_key", "0")
        sf_credential_type = "ACCESS_TOKEN" if sf_password_cred and sf_password_cred != "0" else "KEY_PAIR" 
        print(f"user - {sf_user}  sf_role - {sf_role}   credential type - {sf_credential_type}")
        try:
            sf_admin_secret_id = "mlx.edp.snowflake.MLX_AWS_ADM_USR"
        except Exception as e:
            raise ValueError(f"Invalid Snowflake account '{sf_account}' in secret '{secret_name}'.")

        # Fetch the Admin user credentials from Secrets Manager
        admin_creds = json.loads(client.get_secret_value(SecretId=sf_admin_secret_id)["SecretString"])
        admin_user = admin_creds.get("sfUser")
        #admin_pass = admin_creds.get("sfPassword")
        admin_pass = admin_creds.get("private_key")
        admin_account = admin_creds.get("account")
        if not all([admin_user, admin_pass, admin_account]):
            raise ValueError("Admin secret is missing required fields.")

        '''
        Conditional statement ->
            if env = DEV and sync flag = True:
                Create/Auto rotate key pair/access token in DEV and sync with QA
            else if env = DEV and sync flag = False:
                Create/Auto rotate key pair/access token only in DEV 
            else if env = QA and sync flag = True: 
                Do nothing
            else if env = QA and sync flag = False:
                Create/Auto rotate key pair/access token only in QA
            else if env = PROD: (Irrespective of the sync flag value)
                Create/Auto rotate key pair/access token only in PROD 
        '''
        # (1) If env = DEV and sync flag = True, Create/Auto rotate key pair/access token in DEV and sync with QA ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
        if sf_env.lower() == "dev" and syncflag.lower() == "true":
            new_credential = credential_creation_rotation(client, admin_user, admin_pass, admin_account, sf_user, sf_role, secret_dict, secret_name, secret_arn, sf_credential_type)

            # Sync the newly generated credential in QA account Secrets manager-------------------
            # Retrieve secret key data for Snowflake Service Account user from QA Account
            assumed_role = sts.assume_role(
                RoleArn="arn:aws:iam::873332426699:role/MLX-Sync-Snowflake-Secret-QA",
                RoleSessionName="AssumeRoleSession"
            )
            creds = assumed_role["Credentials"]
            client_qa = boto3.client(
                "secretsmanager",
                region_name="us-east-1",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )

            # Check if Secret_Id is present in QA account Secrets Manager or not,
            #       if yes, then update the secret values with new key/access token
            #       if no, then create a new secret in QA account Secrets manager
            try:
                secret_qa = {}
                response_qa = client_qa.get_secret_value(SecretId=secret_name)
                secret_qa = json.loads(response_qa["SecretString"])
                if sf_credential_type == "KEY_PAIR":
                    secret_qa.update({
                        "private_key": new_credential,
                        "user": sf_user,
                        "account": sf_account,
                        "sfRole": sf_role,
                        "USERNAME": sf_user,
                        "sfUser": sf_user,
                        "updatedate": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                        "environment": "qa",
                        "syncflag": "true"
                    })
                elif sf_credential_type == "ACCESS_TOKEN":
                    secret_qa.update({
                        "sfPassword": new_credential,
                        "PASSWORD": new_credential,
                        "password": new_credential,
                        "user": sf_user,
                        "account": sf_account,
                        "sfRole": sf_role,
                        "USERNAME": sf_user,
                        "sfUser": sf_user,
                        "updatedate": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                        "environment": "qa",
                        "syncflag": "true"
                    })

                if "rotationRetryAttempted" in secret_qa:
                    secret_qa.pop("rotationRetryAttempted", "")

                client_qa.put_secret_value(SecretId=secret_name, SecretString=json.dumps(secret_qa))
                logger.info(f"Successfully synced credentials in QA environment for user '{sf_user}'")
            except client_qa.exceptions.ResourceNotFoundException:
                logger.warning(f"QA secret '{secret_name}' not found, creating new one.")
                if sf_credential_type == "KEY_PAIR":
                    secret_qa.update({
                        "private_key": new_credential,
                        "sfUser": sf_user,
                        "USERNAME": sf_user,
                        "user": sf_user,
                        "account": sf_account,
                        "sfRole": sf_role,
                        "updatedate": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                        "environment": "qa",
                        "syncflag": "true"
                    })
                elif sf_credential_type == "ACCESS_TOKEN":
                    secret_qa.update({
                        "sfPassword": new_credential,
                        "PASSWORD": new_credential,
                        "password": new_credential,
                        "sfUser": sf_user,
                        "USERNAME": sf_user,
                        "user": sf_user,
                        "account": sf_account,
                        "sfRole": sf_role,
                        "updatedate": datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                        "environment": "qa",
                        "syncflag": "true"
                    })

                if "rotationRetryAttempted" in secret_qa:
                    secret_qa.pop("rotationRetryAttempted", "")
                client_qa.create_secret(Name=secret_name, SecretString=json.dumps(secret_qa))

        # (2) If env = DEV and sync flag = False, then create/auto rotate key pair/access token only in DEV ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~     
        elif sf_env.lower() == "dev" and syncflag.lower() == "false":
            credential_creation_rotation(client, admin_user, admin_pass, admin_account, sf_user, sf_role, secret_dict, secret_name, secret_arn, sf_credential_type)
            logger.info(f"Successfully updated the credentials for secret {secret_name} in DEV.")

        # (3) If env = QA and sync flag = True, then do nothing ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
        elif sf_env.lower() == "qa" and syncflag.lower() == "true":
            logger.info("QA secret is synced with DEV. Skipping rotation.")

        # (4) If env = QA and sync flag = False, then create/auto rotate key pair/access token only in QA ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~  
        elif sf_env.lower() == "qa" and syncflag.lower() == "false":
            credential_creation_rotation(client, admin_user, admin_pass, admin_account, sf_user, sf_role, secret_dict, secret_name, secret_arn, sf_credential_type)
            logger.info(f"Successfully updated the credentials for secret {secret_name} in QA.")

        # (5) If env = PROD, then create/auto rotate key pair/access token only in PROD ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~   
        elif sf_env.lower() == "prod":
            credential_creation_rotation(client, admin_user, admin_pass, admin_account, sf_user, sf_role, secret_dict, secret_name, secret_arn, sf_credential_type)
            logger.info(f"Successfully updated the credentials for secret {secret_name} in PROD.")


        # On success, clear retry flag if present. 
        # "rotationRetryAttempted" key is created in the Secret to track the number of times lambda function has been invoked incase of failures.
        if "rotationRetryAttempted" in secret_dict:
            secret_dict.pop("rotationRetryAttempted", "")
            client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(secret_dict))
            logger.info(f"Removed rotationRetryAttempted key from the secret if present.")

        logger.info(f"Credentials rotated successfully and secret updated for user '{sf_user}'")
        return {
            'statusCode': 200,
            'body': json.dumps(f"Credentials rotated successfully and secret updated for user '{sf_user}'")
        }

    except Exception as e:
        logger.exception("Rotation failed.")

        # Re-fetch secret value directly from Secrets Manager
        refreshed_secret = client.get_secret_value(SecretId=secret_id)
        refreshed_dict = json.loads(refreshed_secret.get("SecretString", "{}"))

        # Get value of 'rotationRetryAttempted' from Secret if present, if not, then assign value = 0
        retry_attempted = refreshed_dict.get("rotationRetryAttempted", "0")
        logger.info(f"Retry flag from re-fetched secret: {retry_attempted}")

        '''First failure: This could be because of one of the following reasons - 
            1. Snowflake connectivity failed.
            2. Race condition - When for a username and role combination, while checking, if its found that active key pair/access token exists, so it tried to auto rotate it, 
                but the time it execute the auto rotate query, the existing active key pair/access token expires.
            3. If username or role is not found, or their combination is not present in the key pair table METADATA.CYBER.ACTIVE_SERVICE_USER_ROLE_PAT_STATUS.
        '''
        if retry_attempted == "0":
            logger.warning("First failure. Setting retry flag and allowing Secrets Manager to retry.")
            refreshed_dict["rotationRetryAttempted"] = str(int(retry_attempted) + 1)
            logger.info(f"Rotation retry attempt: {str(int(retry_attempted) + 1)}")
            client.put_secret_value(
                SecretId=secret_id,
                SecretString=json.dumps(refreshed_dict)
            )
            # Invoke the lambda function again as a second attempt.
            lambda_client = boto3.client('lambda')
            lambda_client.invoke(
                FunctionName=os.environ['AWS_MY_LAMBDA_FUNCTION_NAME'],
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(event)
            )
            logger.error(f"Rotation failed at first attempt: {str(e)}")
            return {
                'statusCode': 200,
                'body': json.dumps(f"Rotation failed at first attempt: {str(e)}")
            }
        # Second failure: This happens when the first retry after the first failure fails as well. In this case, we exit and send out an email notification to members mentioned in the SNS topic.
        elif retry_attempted == "1":
            logger.error("Second failure. Sending SNS notification and stopping retries.")
            refreshed_dict["rotationRetryAttempted"] = str(int(retry_attempted) + 1)
            logger.info(f"Rotation retry attempt: {str(int(retry_attempted) + 1)}")
            client.put_secret_value(
                SecretId=secret_id,
                SecretString=json.dumps(refreshed_dict)
            )
            # Call failure notification function to send out an email using SNS topic.
            send_failure_notification(event, str(e), sf_credential_type)
            logger.error(f"Rotation permanently failed: {str(e)}")
            return {
                'statusCode': 200,
                'body': json.dumps(f"Rotation permanently failed: {str(e)}")
            }
        # Anything apart from the above 2 cases, will result in this case, where it will simply exit the code and do nothing.
        else:
            logger.error("More than 2 attempts made. Stopping retries.")
            refreshed_dict["rotationRetryAttempted"] = str(int(retry_attempted) + 1)
            logger.info(f"Rotation retry attempt: {str(int(retry_attempted) + 1)}")
            client.put_secret_value(
                SecretId=secret_id,
                SecretString=json.dumps(refreshed_dict)
            )
            logger.error(f"Rotation permanently failed: {str(e)}")
            return {
                'statusCode': 200,
                'body': json.dumps(f"Rotation permanently failed: {str(e)}")
            }