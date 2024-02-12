# ref: https://github.com/jpf/okta-pysaml2-example/blob/master/app.py
import uuid

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config


app = Flask(__name__)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key

def saml_client_for():
    acs_url = url_for(
        'saml_request',
        _external=True)
    
    settings = {
        'entityid': 'flask',
        'metadata': {
            'remote': [
                {'url': 'http://localhost:18080/realms/myrealm/protocol/saml/descriptor'},
            ],
        },
        'service': {
            'sp': {
                'endpoint': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                    ]
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'want_assertions_signed': False,
                'want_response_signed': False,

            }
        }
    }

    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client

@app.route('/saml/login/keycloak')
def saml_request():
    # SAMLクライアントを生成する
    saml_client = saml_client_for()

    # 認証準備をする
    _reqid, info = saml_client.prepare_for_authenticate()

    # HTTP Redirect Binding のリダイレクト先はLocationヘッダに保存されているため、
    # その値を redirect 関数に渡す
    redirect_url = None
    # Select the IdP URL to send the AuthN request to
    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
    response = redirect(redirect_url, code=302)
    # NOTE:
    #   I realize I _technically_ don't need to set Cache-Control or Pragma:
    #     http://stackoverflow.com/a/5494469
    #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
    #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    #   We set those headers here as a 'belt and suspenders' approach,
    #   since enterprise environments don't always conform to RFCs
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/saml/response/keycloak', methods=['POST'])
def saml_response():
    saml_client = saml_client_for()
    authn_response = saml_client.parse_authn_request_response(
        request.form['SAMLResponse'],
        entity.BINDING_HTTP_POST)

    # parse_assertion()してからでないと、get_identity()やget_subject()で値が取れない
    authn_response.parse_assertion()
    user_info = authn_response.get_subject()

    session['saml_attributes'] = {
        'name_id': user_info.text,
        'name_id_format': user_info.format,
        'name_id_name_qualifier': user_info.name_qualifier,
        'name_id_sp_name_qualifier': user_info.sp_name_qualifier,
        'session_index': authn_response.assertion.authn_statement[0].session_index,
        'session_expiration': authn_response.assertion.authn_statement[0].session_not_on_or_after,
        'message_id': authn_response.response.id,
        'message_issue_instant': authn_response.response.issue_instant,
        'assertion_id': authn_response.assertion.id,
        'assertion_not_on_or_after': authn_response.assertion.issue_instant,
        'relay_status': 'NOT_USED',
        'identity': authn_response.get_identity()
    }

    return redirect('/')

@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=15000, debug=True)