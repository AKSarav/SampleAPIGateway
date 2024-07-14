import json
import os

def lambda_handler(event, context):
  try:
    # Log the received event
    print("Received event:", json.dumps(event))
    
    expected_auth_key = 'X-Auth-Key'
    expected_auth_value = os.environ.get("SP_INTERNAL_KEY")
    expected_api_key_header = 'X-Api-Key'
    expected_api_key_value = os.environ.get("SP_PRIVATE_KEY")
    
    headers = event.get('headers', {})
    
    auth_value = headers.get(expected_auth_key)
    api_key_value = headers.get(expected_api_key_header)
    
    effect = 'Deny'
    principal_id = 'unauthorized_user'
    
    if auth_value == expected_auth_value and api_key_value == expected_api_key_value:
        effect = 'Allow'
        principal_id = 'authorized_user'
    
    # Generate the policy document
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": event['methodArn']
            }
        ]
    }
    
    # Return the authorization response
    auth_response = {
        "principalId": principal_id,
        "policyDocument": policy_document,

    }
    print("Auth response:", json.dumps(auth_response))
  
    return auth_response
  except Exception as e:
    
    # Log the error
    error_message = {
        "errorType": type(e).__name__,
        "errorMessage": str(e),
        "stackTrace": str(e.__traceback__)
    }
    print("Error:", json.dumps(error_message))
    
    # Optionally, return a default deny policy in case of an error
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": "Deny",
                "Resource": event['methodArn']
            }
        ]
    }
    
    auth_response = {
        "principalId": "unauthorized_user",
        "policyDocument": policy_document
    }
    
    return auth_response