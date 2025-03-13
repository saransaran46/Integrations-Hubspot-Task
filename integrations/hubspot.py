import json
import secrets
import base64
import hashlib
import asyncio
import httpx
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem

# HubSpot OAuth Credentials (Replace with actual values)
CLIENT_ID = '0fe9aea8-6f3a-45fb-b86f-daacfe08a67a'
CLIENT_SECRET = '62b49673-f66d-4d06-b365-0296ab0ad307'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'

AUTHORIZATION_URL = "https://app.hubspot.com/oauth/authorize"
TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
scopes = "crm.objects.contacts.read crm.objects.contacts.write"
scope = "%20".join(scopes.split())


async def authorize_hubspot(user_id, org_id):
    """
    Generate the authorization URL for HubSpot OAuth and store state in Redis.
    """
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    auth_url = (
        f"{AUTHORIZATION_URL}?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={scope}"
        f"&state={encoded_state}"
        f"&response_type=code"
    )

    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)

    return auth_url


async def get_hubspot_credentials(user_id, org_id):
    """
    Retrieve stored HubSpot OAuth credentials from Redis.
    """
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found. Please reauthorize.')

    return json.loads(credentials)



async def oauth2callback_hubspot(request: Request):
    """
    Handle OAuth2 callback from HubSpot.
    Exchange authorization code for an access token.
    """
    if "error" in request.query_params:
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))

    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")

    if not code or not encoded_state:
        raise HTTPException(status_code=400, detail="Missing authorization code or state.")

    try:
        state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode())
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid state parameter.")

    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")
    original_state = state_data.get("state")

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    if not saved_state or json.loads(saved_state).get("state") != original_state:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state.")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            TOKEN_URL,
            data={
                'grant_type': 'authorization_code',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'code': code
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to obtain access token.")

    credentials = response.json()
    credentials["user_id"] = user_id
    credentials["org_id"] = org_id

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(credentials), expire=credentials.get("expires_in", 3600))
    await delete_key_redis(f'hubspot_state:{org_id}:{user_id}')

    return HTMLResponse(content="<html><script>window.close();</script></html>")


async def refresh_hubspot_token(user_id, org_id):
    """
    Refresh HubSpot OAuth token if expired.
    """
    credentials = await get_hubspot_credentials(user_id, org_id)
    refresh_token = credentials.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token available.")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            TOKEN_URL,
            data={
                'grant_type': 'refresh_token',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'refresh_token': refresh_token
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to refresh access token")

    new_credentials = response.json()
    new_credentials["user_id"] = user_id
    new_credentials["org_id"] = org_id

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(new_credentials), expire=new_credentials.get("expires_in", 3600))

    return new_credentials


async def get_items_hubspot(user_id, org_id):
    """
    Fetch contacts from HubSpot using stored credentials.
    """
    stored_credentials = await get_hubspot_credentials(user_id, org_id)
    access_token = stored_credentials.get("access_token")

    if not access_token:
        raise HTTPException(status_code=401, detail="Invalid access token. Try reauthorizing.")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.hubapi.com/crm/v3/objects/contacts",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        )

        if response.status_code == 401:
            stored_credentials = await refresh_hubspot_token(user_id, org_id)
            access_token = stored_credentials.get("access_token")

            response = await client.get(
                "https://api.hubapi.com/crm/v3/objects/contacts",
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to fetch items from HubSpot")

    return response.json().get("results", [])


async def clear_hubspot_data(user_id, org_id):
    """
    Clear stored HubSpot credentials and integration data.
    """
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    return {"message": "HubSpot data cleared successfully"}
























# async def refresh_hubspot_token(user_id, org_id):
#     """
#     Refresh HubSpot OAuth token if expired.
#     """
#     credentials = await get_hubspot_credentials(user_id, org_id)
#     refresh_token = credentials.get("refresh_token")

#     if not refresh_token:
#         raise HTTPException(status_code=400, detail="No refresh token available.")

#     async with httpx.AsyncClient() as client:
#         response = await client.post(
#             TOKEN_URL,
#             data={
#                 'grant_type': 'refresh_token',
#                 'client_id': CLIENT_ID,
#                 'client_secret': CLIENT_SECRET,
#                 'refresh_token': refresh_token
#             },
#             headers={'Content-Type': 'application/x-www-form-urlencoded'}
#         )

#     if response.status_code != 200:
#         raise HTTPException(status_code=response.status_code, detail="Failed to refresh access token")

#     new_credentials = response.json()
#     await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(new_credentials), expire=new_credentials.get("expires_in", 3600))

#     return new_credentials


# async def create_integration_item_metadata_object(response_json):
#     """
#     Create an IntegrationItem metadata object from HubSpot response.
#     """
#     print(response_json, 'res-->')

#     return IntegrationItem(
#         id=response_json.get("id"),
#         name=f"{response_json.get('properties', {}).get('firstname', 'Unknown')} {response_json.get('properties', {}).get('lastname', '')}".strip(),
#         created_at=response_json.get("properties", {}).get("createdate"),  # FIX: Get from properties
#         updated_at=response_json.get("properties", {}).get("lastmodifieddate"),  # FIX: Get from properties
#         properties=response_json.get("properties", {}),
#     )



# async def get_items_hubspot(credentials: str):
#     """
#     Fetch contacts from HubSpot using stored credentials.
#     """
#     try:
#         # Parse the credentials JSON string to extract user_id and org_id
#         credentials_dict = json.loads(credentials)
#         user_id = credentials_dict.get("user_id")
#         org_id = credentials_dict.get("org_id")

#         if not user_id or not org_id:
#             raise HTTPException(status_code=400, detail="Missing user_id or org_id in credentials")

#         # Retrieve stored credentials from Redis
#         stored_credentials = await get_hubspot_credentials(user_id, org_id)
#         access_token = stored_credentials.get("access_token")

#         if not access_token:
#             raise HTTPException(status_code=401, detail="Invalid access token. Try reauthorizing.")

#         async with httpx.AsyncClient() as client:
#             response = await client.get(
#                 "https://api.hubapi.com/crm/v3/objects/contacts",
#                 headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
#             )

#             # Handle token expiration
#             if response.status_code == 401:
#                 stored_credentials = await refresh_hubspot_token(user_id, org_id)
#                 access_token = stored_credentials.get("access_token")

#                 response = await client.get(
#                     "https://api.hubapi.com/crm/v3/objects/contacts",
#                     headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
#                 )

#         if response.status_code != 200:
#             raise HTTPException(status_code=response.status_code, detail="Failed to fetch items from HubSpot")

#         return [await create_integration_item_metadata_object(item) for item in response.json().get("results", [])]

#     except json.JSONDecodeError:
#         raise HTTPException(status_code=400, detail="Invalid credentials format. Expected JSON string.")
