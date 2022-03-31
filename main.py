import string, random
from flask import Flask, request, redirect, Response
from base64 import b64encode, b64decode
from urllib.parse import quote_plus, parse_qs, urlparse
from datetime import datetime, timedelta
from lxml import etree
import hmac
import hashlib 

app = Flask(__name__)

sso_secret = '' ## this is set in the discourse login menu
bridge_base_url = 'https://chat.scanlines.xyz/oauth2/auth' ## these must be https
discourse_base_url = 'https://scanlines.xyz' ## these must be https

memory_store = {}


@app.route('/oauth2/auth')
def forward_request():
    '''
        From discourse sso wiki:
        > Generate a random nonce - Save it temporarily so that you can verify it with returned nonce value
        > Create a new payload with nonce and return url (where the Discourse will redirect user after verification). Payload should look like: nonce=NONCE&return_sso_url=RETURN_URL
        > Base64 encode the above raw payload. Let’s call this payload as BASE64_PAYLOAD
        > URL encode the above BASE64_PAYLOAD. Let’s call this payload as URL_ENCODED_PAYLOAD
        > Generate a HMAC-SHA256 signature from BASE64_PAYLOAD using your sso provider secret as the key, then create a lower case hex string from this. Let’s call this signature as HEX_SIGNATURE
        > Redirect the user to DISCOURSE_ROOT_URL/session/sso_provider?sso=URL_ENCODED_PAYLOAD&sig=HEX_SIGNATURE

        note here we use the rocketchat token as nonce
    '''
    global memory_store
    print(request.args)
    # service_url = request.args.get('service')
    return_url = f'{bridge_base_url}/return'
    state = request.args.get('state')
    add_token_to_memory_store(state, memory_store)
    memory_store[state]['code_challenge'] = request.args.get('code_challenge')
    memory_store[state]['redirect_uri'] = request.args.get('redirect_uri')

    payload =f'nonce={state}&return_sso_url={return_url}'
    payload_bytes = payload.encode('ascii')
    base64_bytes = b64encode(payload_bytes)
    base64_payload = base64_bytes.decode('ascii')
    url_encoded_payload = quote_plus(base64_payload)
    hex_signature = create_sha256_signature(sso_secret, base64_payload)

    return redirect(f'{discourse_base_url}/session/sso_provider?sso={url_encoded_payload}&sig={hex_signature}', code=302)


@app.route('/oauth2/auth/return')
def return_request():
    '''
        From discourse sso wiki:
        > Compute the HMAC-SHA256 of sso using sso provider secret as your key.
        > Convert sig from it’s hex string representation back into bytes.
        > Make sure the above two values are equal.
        > Base64 decode sso, you’ll get the passed embedded query string. This will have a key called nonce whose value should match the nonce passed originally. Make sure that this is the case.
        > You’ll find this query string will also contain a bunch of user information, use as you see fit.

        after passing these checks we generate a ticket for this request and put all the info in the memory-store
    '''
    global memory_store
    sso = request.args.get('sso')
    sig = request.args.get('sig')

    sso_signature = create_sha256_signature(sso_secret, sso)
    sso_signature_bytes = sso_signature.encode('utf-8')
    sig_bytes = sig.encode('utf-8')
    if(sso_signature_bytes != sig_bytes):
        print('signature doesnt match')
        return Response('request failed', 401)
    
    embedded_query_bytes = b64decode(sso)
    embedded_query = embedded_query_bytes.decode('ascii')
    query_dict = parse_qs(embedded_query)

    token = query_dict.get('nonce')[0]
    print('token: ', token)
    if not token in memory_store:
        print('token not in store')
        return Response('request failed', 401) 
    
    memory_store[token].update(query_dict)
    code = ''.join([random.choice(string.ascii_lowercase) for _ in range(10)])
    memory_store[token]['code'] = code

    redirect_uri = memory_store[token]['redirect_uri']
    return redirect(f'{redirect_uri}?code={code}&state={token}', code=302)


@app.route('/oauth2/token')
def validate_request():
    '''
        check that the ticket send matches the ticket returned. then generate xml for user info
    '''
    global memory_store

    print('args: ', request.args)
    # service_url = request.args.get('service')
    # token = urlparse(service_url).path.split('/')[-1]
    # if not token in memory_store:
    #     print('token not in store')
    #     return Response('request failed', 401) 

    # if memory_store[token]['ticket'] != returned_ticket:
    #     print('ticket doesnt match')
    #     return Response('request failed', 401) 



    # del memory_store[token]
    
    return Response('request failed', 401)


def create_sha256_signature(key, message):
    byte_key = key.encode('utf-8')
    byte_message = message.encode('utf-8')
    return hmac.new(byte_key, byte_message, hashlib.sha256).hexdigest().lower()


def add_token_to_memory_store(new_token, memory_store):
    expires = datetime.now() + timedelta(minutes=10)
    memory_store[new_token] = {'expires_at': expires }
    # remove expired tokens from store
    memory_store = {token:content for token, content in memory_store.items() if content['expires_at'] > datetime.now()}


if __name__ == "__main__":
    app.run(host='0.0.0.0')